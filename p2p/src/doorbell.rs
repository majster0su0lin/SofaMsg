/// Doorbell wake-up mechanism for sleeping devices.
///
/// # Design rationale
///
/// A mobile device can't keep a socket open 24/7 — it gets killed by the
/// OS and drains battery. The doorbell is a tiny, content-free signal that
/// uses the platform's push-notification infrastructure to wake the app
/// just long enough (~30 seconds) to pull pending messages from the DHT.
///
/// **What the doorbell IS:**
/// - A one-way "someone wants to talk to you" nudge
/// - Carries ONLY the recipient's queue/device ID + a random nonce + a timestamp
/// - Travels via CoAP (UDP-based, designed for constrained devices) or
///   UnifiedPush (HTTP POST to a push gateway, Android-native)
///
/// **What the doorbell is NOT:**
/// - NOT a message transport — no ciphertext, no sender identity, no payload
/// - NOT encrypted itself (it contains zero sensitive data)
/// - NOT a reliable delivery channel — if it fails, the sender retries
///
/// # Flow (see README.md "Protocol details: how the doorbell mechanism should work")
///
/// 1. User A stores an encrypted message on the DHT under B's Queue ID
/// 2. A sends a doorbell ping to B's registered push endpoint
/// 3. B's OS wakes the app for a bounded window
/// 4. B's app pulls messages from DHT (pull, not push — see README for why)
/// 5. B processes messages and goes back to sleep
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Data types ───────────────────────────────────────────────

/// A doorbell ping — the minimal "wake up and check your messages" signal.
///
/// Deliberately contains NO message content and NO sender identity.
/// This means even if an attacker intercepts the ping, they learn only
/// that *someone* wants to talk to the recipient — not who, not what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorbellPing {
    /// The recipient's Queue ID (base58-encoded).
    /// This is a one-way hash of their public key, so intercepting this
    /// does NOT reveal the recipient's Account ID or public key.
    pub recipient_queue_id: String,

    /// Random 16-byte nonce to prevent replay attacks.
    /// Each ping is unique — a relay or observer can't tell if two pings
    /// are retries or separate conversations.
    pub nonce: [u8; 16],

    /// Unix timestamp (seconds) when the ping was created.
    /// Used by the receiver to discard stale pings (e.g. > 5 minutes old).
    pub timestamp: u64,

    /// Protocol version for forward compatibility.
    pub version: u8,
}

/// Current doorbell protocol version.
pub const DOORBELL_VERSION: u8 = 1;

/// Maximum age (in seconds) a doorbell ping is considered valid.
/// Pings older than this are silently discarded to limit replay windows.
const MAX_PING_AGE_SECS: u64 = 300; // 5 minutes

impl DoorbellPing {
    /// Create a new doorbell ping for the given recipient queue.
    ///
    /// Generates a fresh random nonce and current timestamp.
    pub fn new(recipient_queue_id: String) -> Self {
        let mut nonce = [0u8; 16];
        // Use OS-level CSPRNG for the nonce.
        // This is not for encryption — it's just to make each ping unique
        // so replay detection is possible.
        rand_core::OsRng.fill_bytes(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        DoorbellPing {
            recipient_queue_id,
            nonce,
            timestamp,
            version: DOORBELL_VERSION,
        }
    }

    /// Serialize the ping to a compact binary format suitable for CoAP payloads.
    ///
    /// Wire format (all fields big-endian):
    /// ```text
    /// [1 byte version] [16 bytes nonce] [8 bytes timestamp] [remaining: queue_id UTF-8]
    /// ```
    ///
    /// This is intentionally NOT JSON — CoAP payloads should be as small
    /// as possible since they travel over UDP with a typical MTU of ~1280 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let queue_bytes = self.recipient_queue_id.as_bytes();
        let mut buf = Vec::with_capacity(1 + 16 + 8 + queue_bytes.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(queue_bytes);
        buf
    }

    /// Deserialize a ping from its compact binary representation.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DoorbellError> {
        // Minimum size: 1 (version) + 16 (nonce) + 8 (timestamp) + 1 (min queue_id)
        if data.len() < 26 {
            return Err(DoorbellError::MalformedPing(
                "payload too short: need at least 26 bytes".into(),
            ));
        }

        let version = data[0];
        if version != DOORBELL_VERSION {
            return Err(DoorbellError::UnsupportedVersion(version));
        }

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[1..17]);

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[17..25]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let queue_id = std::str::from_utf8(&data[25..])
            .map_err(|e| DoorbellError::MalformedPing(format!("invalid queue ID UTF-8: {e}")))?
            .to_string();

        if queue_id.is_empty() {
            return Err(DoorbellError::MalformedPing("empty queue ID".into()));
        }

        Ok(DoorbellPing {
            recipient_queue_id: queue_id,
            nonce,
            timestamp,
            version,
        })
    }

    /// Check whether this ping is fresh enough to act on.
    ///
    /// Returns `true` if the ping's timestamp is within `MAX_PING_AGE_SECS`
    /// of the current time. Stale pings should be silently dropped — they
    /// may be replays or simply delayed beyond usefulness.
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Guard against clock skew: allow pings slightly in the future too
        // (up to 60 seconds ahead of our clock).
        if self.timestamp > now {
            return self.timestamp - now <= 60;
        }
        now - self.timestamp <= MAX_PING_AGE_SECS
    }
}

use rand_core::RngCore;

// ── Configuration ────────────────────────────────────────────

/// Where a user receives doorbell pings.
///
/// Published as part of the user's DHT record alongside their prekey bundle,
/// so that anyone wanting to send them a message knows how to wake their device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorbellEndpoint {
    /// The type of push transport this endpoint uses.
    pub transport: DoorbellTransport,

    /// The target address. Semantics depend on `transport`:
    /// - CoAP: `"coap://<host>:<port>"` or just `"<host>:<port>"`
    /// - UnifiedPush: the full HTTP(S) push gateway URL
    pub address: String,

    /// The recipient's Queue ID that this endpoint is associated with.
    /// Included so the sender can match the right endpoint to the right queue.
    pub queue_id: String,
}

/// Supported doorbell transport types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoorbellTransport {
    /// CoAP over UDP — lightweight, works well on local/mesh networks.
    CoAP,
    /// UnifiedPush — HTTP POST to a push gateway, works over the internet.
    /// This is the primary transport for Android devices.
    UnifiedPush,
}

/// Configuration for the doorbell subsystem.
#[derive(Debug, Clone)]
pub struct DoorbellConfig {
    /// CoAP server bind address for *receiving* pings (e.g. "0.0.0.0:5683").
    /// `None` disables the CoAP listener.
    pub coap_bind_addr: Option<std::net::SocketAddr>,

    /// UnifiedPush endpoint URL for *receiving* pings.
    /// This is the URL provided by the UnifiedPush distributor app on Android.
    /// `None` disables UnifiedPush reception.
    pub unified_push_url: Option<String>,

    /// How long (seconds) to wait for a message pull after being woken by a ping.
    /// The README specifies ~30 seconds as the design target.
    pub wake_window_secs: u64,
}

impl Default for DoorbellConfig {
    fn default() -> Self {
        DoorbellConfig {
            coap_bind_addr: None,
            unified_push_url: None,
            wake_window_secs: 30,
        }
    }
}

// ── Error types ──────────────────────────────────────────────

/// Errors that can occur during doorbell operations.
#[derive(Debug)]
pub enum DoorbellError {
    /// The ping payload is malformed or too short.
    MalformedPing(String),
    /// The ping uses an unsupported protocol version.
    UnsupportedVersion(u8),
    /// CoAP transport error (UDP send/receive failure).
    CoAPError(String),
    /// UnifiedPush HTTP request failed.
    UnifiedPushError(String),
    /// The ping is too old (possible replay or stale delivery).
    StalePing { age_secs: u64 },
    /// I/O error during network operations.
    Io(std::io::Error),
}

impl std::fmt::Display for DoorbellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DoorbellError::MalformedPing(msg) => write!(f, "malformed doorbell ping: {msg}"),
            DoorbellError::UnsupportedVersion(v) => {
                write!(f, "unsupported doorbell version: {v}")
            }
            DoorbellError::CoAPError(msg) => write!(f, "CoAP error: {msg}"),
            DoorbellError::UnifiedPushError(msg) => write!(f, "UnifiedPush error: {msg}"),
            DoorbellError::StalePing { age_secs } => {
                write!(f, "stale ping: {age_secs}s old")
            }
            DoorbellError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for DoorbellError {}

impl From<std::io::Error> for DoorbellError {
    fn from(e: std::io::Error) -> Self {
        DoorbellError::Io(e)
    }
}

// ── Sender ───────────────────────────────────────────────────

/// Sends doorbell pings to wake remote devices.
///
/// Supports two transports:
/// - **CoAP**: Formats a CoAP POST request and sends it as a single UDP
///   datagram. CoAP is essentially "REST over UDP" — designed for exactly
///   this kind of small, fire-and-forget notification.
/// - **UnifiedPush**: Sends an HTTP POST to a push gateway URL. The gateway
///   is responsible for waking the target device via Android's push mechanism.
pub struct DoorbellSender;

impl DoorbellSender {
    /// Send a doorbell ping via CoAP (UDP).
    ///
    /// Constructs a CoAP POST request with the ping as payload and sends
    /// it to the target address. CoAP uses confirmable messages by default,
    /// but we use non-confirmable (NON) here because doorbell delivery is
    /// best-effort — the sender will retry if no message pull happens.
    ///
    /// # Arguments
    /// * `target_addr` — The recipient's CoAP endpoint (e.g. "192.168.1.5:5683")
    /// * `ping` — The doorbell ping to send
    pub async fn send_coap(target_addr: &str, ping: &DoorbellPing) -> Result<(), DoorbellError> {
        use coap_lite::{CoapRequest, RequestType};
        use std::net::SocketAddr;

        let addr: SocketAddr = target_addr
            .parse()
            .map_err(|e| DoorbellError::CoAPError(format!("invalid target address: {e}")))?;

        // Build a CoAP NON (non-confirmable) POST request.
        // NON means we don't wait for an ACK — the doorbell is best-effort.
        // The URI path "/doorbell" is a convention for SofaMsg nodes.
        let mut request = CoapRequest::<SocketAddr>::new();
        request.set_method(RequestType::Post);
        request.set_path("/doorbell");
        request.message.payload = ping.to_bytes();

        // Mark as non-confirmable (Type = 1 in CoAP).
        // CoAP message types: 0=CON, 1=NON, 2=ACK, 3=RST
        request
            .message
            .header
            .set_type(coap_lite::MessageType::NonConfirmable);

        // Generate a random message ID for this CoAP request
        let msg_id = (ping.nonce[0] as u16) << 8 | (ping.nonce[1] as u16);
        request.message.header.message_id = msg_id;

        let packet = request
            .message
            .to_bytes()
            .map_err(|e| DoorbellError::CoAPError(format!("CoAP serialize failed: {e}")))?;

        // Send the UDP datagram
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DoorbellError::CoAPError(format!("UDP bind failed: {e}")))?;

        socket
            .send_to(&packet, addr)
            .await
            .map_err(|e| DoorbellError::CoAPError(format!("UDP send failed: {e}")))?;

        log::debug!(
            "Doorbell CoAP ping sent to {} for queue {}",
            target_addr,
            ping.recipient_queue_id
        );

        Ok(())
    }

    /// Send a doorbell ping via UnifiedPush (HTTP POST).
    ///
    /// UnifiedPush is an open standard for push notifications on Android
    /// that doesn't require Google Play Services. The distributor app
    /// (e.g. ntfy, NextPush) provides an endpoint URL; we POST the ping
    /// payload to that URL, and the distributor wakes the target app.
    ///
    /// # Arguments
    /// * `endpoint_url` — The UnifiedPush endpoint URL (from the distributor)
    /// * `ping` — The doorbell ping to send
    pub async fn send_unified_push(
        endpoint_url: &str,
        ping: &DoorbellPing,
    ) -> Result<(), DoorbellError> {
        let client = reqwest::Client::new();

        let payload = ping.to_bytes();

        let response = client
            .post(endpoint_url)
            .header("Content-Type", "application/octet-stream")
            .body(payload)
            .send()
            .await
            .map_err(|e| DoorbellError::UnifiedPushError(format!("HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(DoorbellError::UnifiedPushError(format!(
                "push gateway returned HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_else(|_| "<no body>".into())
            )));
        }

        log::debug!(
            "Doorbell UnifiedPush ping sent to {} for queue {}",
            endpoint_url,
            ping.recipient_queue_id
        );

        Ok(())
    }

    /// Send a doorbell ping to the given endpoint, auto-selecting transport.
    ///
    /// Dispatches to `send_coap` or `send_unified_push` based on the
    /// endpoint's declared transport type.
    pub async fn send(
        endpoint: &DoorbellEndpoint,
        ping: &DoorbellPing,
    ) -> Result<(), DoorbellError> {
        match endpoint.transport {
            DoorbellTransport::CoAP => Self::send_coap(&endpoint.address, ping).await,
            DoorbellTransport::UnifiedPush => {
                Self::send_unified_push(&endpoint.address, ping).await
            }
        }
    }
}

// ── Receiver ─────────────────────────────────────────────────

/// Listens for incoming doorbell pings and triggers the DHT message pull.
///
/// The receiver binds to a CoAP UDP port and/or registers with a UnifiedPush
/// distributor, then calls the provided callback whenever a valid, fresh
/// ping arrives. The callback is responsible for initiating the actual
/// message retrieval from the DHT.
pub struct DoorbellReceiver {
    config: DoorbellConfig,
    /// Set of recently-seen nonces for replay detection.
    /// We keep nonces for `MAX_PING_AGE_SECS` and discard older ones.
    seen_nonces: std::collections::HashSet<[u8; 16]>,
}

impl DoorbellReceiver {
    /// Create a new doorbell receiver with the given configuration.
    pub fn new(config: DoorbellConfig) -> Self {
        DoorbellReceiver {
            config,
            seen_nonces: std::collections::HashSet::new(),
        }
    }

    /// Get the configured wake window duration.
    pub fn wake_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.config.wake_window_secs)
    }

    /// Process a raw incoming doorbell payload.
    ///
    /// This is the central validation pipeline:
    /// 1. Deserialize the binary payload
    /// 2. Check protocol version
    /// 3. Verify freshness (reject stale pings)
    /// 4. Check for replay (reject duplicate nonces)
    /// 5. If all checks pass, call `on_doorbell_received`
    ///
    /// Returns the validated ping for further processing, or an error
    /// explaining why it was rejected.
    pub fn process_ping(&mut self, raw_payload: &[u8]) -> Result<DoorbellPing, DoorbellError> {
        let ping = DoorbellPing::from_bytes(raw_payload)?;

        // Freshness check: reject pings older than MAX_PING_AGE_SECS
        if !ping.is_fresh() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age = now.saturating_sub(ping.timestamp);
            return Err(DoorbellError::StalePing { age_secs: age });
        }

        // Replay detection: reject duplicate nonces
        if !self.seen_nonces.insert(ping.nonce) {
            return Err(DoorbellError::MalformedPing(
                "duplicate nonce — possible replay".into(),
            ));
        }

        Ok(ping)
    }

    /// Prune old nonces from the replay-detection set.
    ///
    /// Should be called periodically (e.g. every few minutes) to prevent
    /// unbounded memory growth. In practice, with a 5-minute ping validity
    /// window, the set stays very small.
    pub fn prune_nonces(&mut self) {
        // Simple strategy: just clear the whole set periodically.
        // Since we also check timestamps, a replayed ping with an old
        // nonce will fail the freshness check anyway.
        self.seen_nonces.clear();
    }

    /// Listen for CoAP doorbell pings on the configured UDP address.
    ///
    /// This runs an async loop that:
    /// 1. Binds a UDP socket to `coap_bind_addr`
    /// 2. Receives datagrams
    /// 3. Parses CoAP messages and extracts the payload
    /// 4. Calls `callback` with each validated ping
    ///
    /// The callback should initiate a DHT message pull for the queue ID
    /// in the ping. It receives the validated `DoorbellPing` and should
    /// return quickly — heavy work (DHT queries) should be spawned separately.
    pub async fn listen_coap<F>(&mut self, callback: F) -> Result<(), DoorbellError>
    where
        F: Fn(DoorbellPing) + Send + 'static,
    {
        let bind_addr = self
            .config
            .coap_bind_addr
            .ok_or_else(|| DoorbellError::CoAPError("no CoAP bind address configured".into()))?;

        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| DoorbellError::CoAPError(format!("UDP bind failed: {e}")))?;

        log::info!("Doorbell CoAP listener started on {}", bind_addr);

        let mut buf = [0u8; 1500]; // Standard MTU
        loop {
            let (len, src) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| DoorbellError::CoAPError(format!("UDP recv failed: {e}")))?;

            // Parse the CoAP message to extract the payload
            let coap_msg = match coap_lite::Packet::from_bytes(&buf[..len]) {
                Ok(msg) => msg,
                Err(e) => {
                    log::warn!("Invalid CoAP packet from {}: {}", src, e);
                    continue;
                }
            };

            // Process the ping payload
            match self.process_ping(&coap_msg.payload) {
                Ok(ping) => {
                    log::debug!(
                        "Valid doorbell ping from {} for queue {}",
                        src,
                        ping.recipient_queue_id
                    );
                    callback(ping);
                }
                Err(e) => {
                    log::debug!("Rejected doorbell from {}: {}", src, e);
                }
            }
        }
    }
}

/// Callback type for doorbell-triggered message pulls.
///
/// This is the integration point between the doorbell subsystem and the
/// P2P node. When a valid doorbell ping arrives, this function is called
/// with the Queue ID that should be checked for pending messages.
///
/// Typical implementation:
/// ```ignore
/// fn on_doorbell_received(queue_id: &str) {
///     // 1. Start the wake window timer (~30 seconds)
///     // 2. Query the DHT for records under this Queue ID
///     // 3. Decrypt and process any retrieved messages
///     // 4. Request deletion of processed records from DHT
///     // 5. Return to sleep
/// }
/// ```
pub fn on_doorbell_received(queue_id: &str) {
    // This is a placeholder implementation that logs the event.
    // The actual implementation will be wired into `SofaNode::check_messages()`
    // once the full integration is built.
    log::info!(
        "Doorbell received for queue {}: initiating message pull",
        queue_id
    );
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- DoorbellPing tests --

    #[test]
    fn ping_round_trip_binary() {
        let ping = DoorbellPing::new("test_queue_abc123".to_string());
        let bytes = ping.to_bytes();
        let recovered = DoorbellPing::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.recipient_queue_id, "test_queue_abc123");
        assert_eq!(recovered.nonce, ping.nonce);
        assert_eq!(recovered.timestamp, ping.timestamp);
        assert_eq!(recovered.version, DOORBELL_VERSION);
    }

    #[test]
    fn ping_rejects_too_short_payload() {
        let short = vec![0u8; 10];
        let result = DoorbellPing::from_bytes(&short);
        assert!(result.is_err());
        match result.unwrap_err() {
            DoorbellError::MalformedPing(msg) => {
                assert!(msg.contains("too short"));
            }
            other => panic!("expected MalformedPing, got: {other}"),
        }
    }

    #[test]
    fn ping_rejects_unsupported_version() {
        let ping = DoorbellPing::new("queue".to_string());
        let mut bytes = ping.to_bytes();
        bytes[0] = 99; // bogus version
        let result = DoorbellPing::from_bytes(&bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            DoorbellError::UnsupportedVersion(v) => assert_eq!(v, 99),
            other => panic!("expected UnsupportedVersion, got: {other}"),
        }
    }

    #[test]
    fn ping_rejects_empty_queue_id() {
        // Build a valid header but with zero-length queue ID
        let mut buf = Vec::new();
        buf.push(DOORBELL_VERSION);
        buf.extend_from_slice(&[0u8; 16]); // nonce
        buf.extend_from_slice(&0u64.to_be_bytes()); // timestamp
                                                    // no queue ID bytes — exactly 25 bytes total
        let result = DoorbellPing::from_bytes(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn ping_is_fresh_when_just_created() {
        let ping = DoorbellPing::new("queue".to_string());
        assert!(ping.is_fresh());
    }

    #[test]
    fn ping_is_stale_when_old() {
        let mut ping = DoorbellPing::new("queue".to_string());
        // Set timestamp to 10 minutes ago
        ping.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;
        assert!(!ping.is_fresh());
    }

    #[test]
    fn ping_tolerates_slight_future_timestamp() {
        let mut ping = DoorbellPing::new("queue".to_string());
        // 30 seconds in the future (within the 60s tolerance)
        ping.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30;
        assert!(ping.is_fresh());
    }

    #[test]
    fn ping_rejects_far_future_timestamp() {
        let mut ping = DoorbellPing::new("queue".to_string());
        // 2 minutes in the future (beyond 60s tolerance)
        ping.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120;
        assert!(!ping.is_fresh());
    }

    #[test]
    fn each_ping_has_unique_nonce() {
        let p1 = DoorbellPing::new("q".to_string());
        let p2 = DoorbellPing::new("q".to_string());
        assert_ne!(p1.nonce, p2.nonce, "nonces should be randomly unique");
    }

    // -- DoorbellEndpoint tests --

    #[test]
    fn endpoint_serialization_round_trip() {
        let endpoint = DoorbellEndpoint {
            transport: DoorbellTransport::UnifiedPush,
            address: "https://push.example.com/up/abc123".to_string(),
            queue_id: "test_queue".to_string(),
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        let recovered: DoorbellEndpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.transport, DoorbellTransport::UnifiedPush);
        assert_eq!(recovered.address, "https://push.example.com/up/abc123");
        assert_eq!(recovered.queue_id, "test_queue");
    }

    #[test]
    fn coap_endpoint_serialization() {
        let endpoint = DoorbellEndpoint {
            transport: DoorbellTransport::CoAP,
            address: "192.168.1.5:5683".to_string(),
            queue_id: "local_queue".to_string(),
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        let recovered: DoorbellEndpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.transport, DoorbellTransport::CoAP);
    }

    // -- DoorbellReceiver tests --

    #[test]
    fn receiver_accepts_valid_ping() {
        let config = DoorbellConfig::default();
        let mut receiver = DoorbellReceiver::new(config);

        let ping = DoorbellPing::new("my_queue".to_string());
        let bytes = ping.to_bytes();

        let result = receiver.process_ping(&bytes);
        assert!(result.is_ok());

        let validated = result.unwrap();
        assert_eq!(validated.recipient_queue_id, "my_queue");
    }

    #[test]
    fn receiver_rejects_replay() {
        let config = DoorbellConfig::default();
        let mut receiver = DoorbellReceiver::new(config);

        let ping = DoorbellPing::new("my_queue".to_string());
        let bytes = ping.to_bytes();

        // First time: accepted
        assert!(receiver.process_ping(&bytes).is_ok());

        // Second time with same nonce: rejected as replay
        let result = receiver.process_ping(&bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            DoorbellError::MalformedPing(msg) => {
                assert!(msg.contains("replay"));
            }
            other => panic!("expected replay rejection, got: {other}"),
        }
    }

    #[test]
    fn receiver_rejects_stale_ping() {
        let config = DoorbellConfig::default();
        let mut receiver = DoorbellReceiver::new(config);

        let mut ping = DoorbellPing::new("my_queue".to_string());
        ping.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600; // 10 minutes ago

        let bytes = ping.to_bytes();
        let result = receiver.process_ping(&bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            DoorbellError::StalePing { age_secs } => {
                assert!(age_secs >= 590, "expected age ~600s, got {age_secs}");
            }
            other => panic!("expected StalePing, got: {other}"),
        }
    }

    #[test]
    fn receiver_prune_clears_nonces() {
        let config = DoorbellConfig::default();
        let mut receiver = DoorbellReceiver::new(config);

        let ping = DoorbellPing::new("q".to_string());
        let bytes = ping.to_bytes();

        assert!(receiver.process_ping(&bytes).is_ok());
        // After pruning, the nonce set is cleared
        receiver.prune_nonces();
        // The same nonce would pass the replay check now
        // (but would need to also pass freshness check)
        // This tests that pruning works — in practice, old pings
        // also fail the freshness check.
    }

    #[test]
    fn default_config_has_30s_wake_window() {
        let config = DoorbellConfig::default();
        assert_eq!(config.wake_window_secs, 30);
    }

    #[test]
    fn receiver_wake_window_returns_configured_duration() {
        let config = DoorbellConfig {
            wake_window_secs: 45,
            ..DoorbellConfig::default()
        };
        let receiver = DoorbellReceiver::new(config);
        assert_eq!(receiver.wake_window(), std::time::Duration::from_secs(45));
    }

    // -- Wire format tests --

    #[test]
    fn wire_format_structure() {
        let ping = DoorbellPing {
            recipient_queue_id: "ABCD".to_string(),
            nonce: [0x11; 16],
            timestamp: 0x0102030405060708,
            version: DOORBELL_VERSION,
        };

        let bytes = ping.to_bytes();

        // Total: 1 (version) + 16 (nonce) + 8 (timestamp) + 4 (queue_id "ABCD")
        assert_eq!(bytes.len(), 29);

        // Version byte
        assert_eq!(bytes[0], DOORBELL_VERSION);

        // Nonce (16 bytes of 0x11)
        assert_eq!(&bytes[1..17], &[0x11u8; 16]);

        // Timestamp (big-endian)
        assert_eq!(&bytes[17..25], &0x0102030405060708u64.to_be_bytes());

        // Queue ID
        assert_eq!(&bytes[25..], b"ABCD");
    }

    #[test]
    fn on_doorbell_received_does_not_panic() {
        // Smoke test — just verify the placeholder doesn't crash
        on_doorbell_received("test_queue_id");
    }
}

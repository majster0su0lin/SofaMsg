/// Connection invitation — QR code and URI-based out-of-band contact exchange.
///
/// # Purpose
///
/// When two SofaMsg users want to start a conversation, they need to exchange:
/// - Their Account ID (so the other side can identify them)
/// - Their public key (so the other side can encrypt messages to them)
/// - Their Queue ID (so the other side knows where to store messages on the DHT)
///
/// This module provides two formats for encoding that information:
///
/// 1. **URI format** (`sofamsg://connect?v=1&key=...&queue=...&name=...`)
///    — for clickable links shared via other messaging apps, email, etc.
///
/// 2. **Compact binary format** — for QR codes, where every byte counts
///    because larger payloads require denser (harder to scan) QR codes.
///
/// # Security
///
/// The invitation contains ONLY public information. No secrets are included.
/// The `validate()` method re-derives the Account ID from the public key bytes
/// to detect tampering — if someone modifies the public key in a shared link,
/// the Account ID won't match and the invite is rejected.
use sha2::{Digest, Sha256};

/// The URI scheme used for SofaMsg invitation links.
const URI_SCHEME: &str = "sofamsg";

/// The URI host/authority for connection invitations.
const URI_HOST: &str = "connect";

/// Current invitation protocol version.
const INVITE_VERSION: u8 = 1;

/// Prefix used for Account IDs (must match core::identity).
const ACCOUNT_ID_PREFIX: &str = "sb_";

/// A connection invitation payload.
///
/// Contains everything a peer needs to initiate contact:
/// - Who you are (account_id, public key)
/// - Where to reach you (queue_id)
/// - What protocol version to use
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePayload {
    /// The sender's Account ID (e.g. "sb_5Hq3r...").
    /// Derived from the public key via SHA-256 + base58 + "sb_" prefix.
    pub account_id: String,

    /// The sender's Ed25519 public key, base58-encoded.
    /// 32 bytes of raw key → ~44 characters of base58.
    pub public_key_b58: String,

    /// The sender's Queue ID, base58-encoded.
    /// This is where messages for this user are stored on the DHT.
    pub queue_id_b58: String,

    /// Optional display name. Not cryptographically verified — purely
    /// for human convenience (e.g. showing "Alice wants to connect").
    pub display_name: Option<String>,

    /// Protocol version. Used for forward compatibility — a newer client
    /// can still parse an older invitation format.
    pub version: u8,
}

/// Errors that can occur when parsing or validating invitations.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    /// The URI scheme is not "sofamsg".
    InvalidScheme(String),
    /// The URI host/path is not "connect".
    InvalidHost(String),
    /// A required query parameter is missing.
    MissingField(String),
    /// A field has an invalid value.
    InvalidField { field: String, reason: String },
    /// The Account ID doesn't match the public key (possible tampering).
    AccountIdMismatch { expected: String, actual: String },
    /// The binary payload is too short or malformed.
    MalformedBinary(String),
    /// The invitation uses an unsupported protocol version.
    UnsupportedVersion(u8),
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InviteError::InvalidScheme(s) => {
                write!(f, "invalid URI scheme: expected 'sofamsg', got '{s}'")
            }
            InviteError::InvalidHost(h) => {
                write!(f, "invalid URI host: expected 'connect', got '{h}'")
            }
            InviteError::MissingField(field) => {
                write!(f, "missing required field: {field}")
            }
            InviteError::InvalidField { field, reason } => {
                write!(f, "invalid field '{field}': {reason}")
            }
            InviteError::AccountIdMismatch { expected, actual } => {
                write!(
                    f,
                    "account ID mismatch: key derives '{expected}', invite says '{actual}'"
                )
            }
            InviteError::MalformedBinary(msg) => {
                write!(f, "malformed binary invite: {msg}")
            }
            InviteError::UnsupportedVersion(v) => {
                write!(f, "unsupported invite version: {v}")
            }
        }
    }
}

impl std::error::Error for InviteError {}

impl InvitePayload {
    /// Create a new invitation payload.
    ///
    /// # Arguments
    /// * `public_key_bytes` — The 32-byte Ed25519 public key
    /// * `queue_id_bytes` — The 32-byte Queue ID (raw hash)
    /// * `display_name` — Optional human-readable name
    pub fn new(
        public_key_bytes: &[u8; 32],
        queue_id_bytes: &[u8; 32],
        display_name: Option<String>,
    ) -> Self {
        // Derive account ID the same way core::identity does:
        // SHA-256(public_key) → base58 → "sb_" prefix
        let hash = Sha256::digest(public_key_bytes);
        let account_id = format!("{}{}", ACCOUNT_ID_PREFIX, bs58::encode(hash).into_string());

        let public_key_b58 = bs58::encode(public_key_bytes).into_string();
        let queue_id_b58 = bs58::encode(queue_id_bytes).into_string();

        InvitePayload {
            account_id,
            public_key_b58,
            queue_id_b58,
            display_name,
            version: INVITE_VERSION,
        }
    }

    /// Encode the invitation as a `sofamsg://` URI.
    ///
    /// Format: `sofamsg://connect?v=1&key=<base58>&queue=<base58>&name=<url-encoded>`
    ///
    /// The `name` parameter is omitted if no display name is set.
    /// All values are URL-encoded to handle special characters safely.
    pub fn to_uri(&self) -> String {
        let mut uri = format!(
            "{}://{}?v={}&id={}&key={}&queue={}",
            URI_SCHEME,
            URI_HOST,
            self.version,
            Self::uri_encode(&self.account_id),
            &self.public_key_b58, // base58 is URI-safe, no encoding needed
            &self.queue_id_b58,   // base58 is URI-safe
        );

        if let Some(ref name) = self.display_name {
            uri.push_str("&name=");
            uri.push_str(&Self::uri_encode(name));
        }

        uri
    }

    /// Parse an invitation from a `sofamsg://` URI.
    ///
    /// Validates the scheme, host, and required parameters. Does NOT
    /// validate the account ID against the public key — call `validate()`
    /// separately for that.
    pub fn from_uri(uri: &str) -> Result<Self, InviteError> {
        // Split scheme from rest: "sofamsg://connect?..."
        let (scheme, rest) = uri
            .split_once("://")
            .ok_or_else(|| InviteError::InvalidScheme("no :// found".into()))?;

        if scheme != URI_SCHEME {
            return Err(InviteError::InvalidScheme(scheme.to_string()));
        }

        // Split host from query: "connect?v=1&key=..."
        let (host, query) = rest
            .split_once('?')
            .ok_or_else(|| InviteError::InvalidHost("no query string".into()))?;

        if host != URI_HOST {
            return Err(InviteError::InvalidHost(host.to_string()));
        }

        // Parse query parameters
        let params = Self::parse_query(query);

        let version_str = params
            .get("v")
            .ok_or_else(|| InviteError::MissingField("v (version)".into()))?;
        let version: u8 = version_str.parse().map_err(|_| InviteError::InvalidField {
            field: "v".into(),
            reason: format!("not a valid u8: '{version_str}'"),
        })?;

        if version != INVITE_VERSION {
            return Err(InviteError::UnsupportedVersion(version));
        }

        let account_id = params
            .get("id")
            .ok_or_else(|| InviteError::MissingField("id (account ID)".into()))?
            .clone();

        if !account_id.starts_with(ACCOUNT_ID_PREFIX) {
            return Err(InviteError::InvalidField {
                field: "id".into(),
                reason: format!("must start with '{ACCOUNT_ID_PREFIX}'"),
            });
        }

        let public_key_b58 = params
            .get("key")
            .ok_or_else(|| InviteError::MissingField("key (public key)".into()))?
            .clone();

        // Validate that the base58 decodes to exactly 32 bytes
        let key_bytes =
            bs58::decode(&public_key_b58)
                .into_vec()
                .map_err(|e| InviteError::InvalidField {
                    field: "key".into(),
                    reason: format!("invalid base58: {e}"),
                })?;
        if key_bytes.len() != 32 {
            return Err(InviteError::InvalidField {
                field: "key".into(),
                reason: format!("expected 32 bytes, got {}", key_bytes.len()),
            });
        }

        let queue_id_b58 = params
            .get("queue")
            .ok_or_else(|| InviteError::MissingField("queue (Queue ID)".into()))?
            .clone();

        // Validate queue ID decodes to 32 bytes
        let queue_bytes =
            bs58::decode(&queue_id_b58)
                .into_vec()
                .map_err(|e| InviteError::InvalidField {
                    field: "queue".into(),
                    reason: format!("invalid base58: {e}"),
                })?;
        if queue_bytes.len() != 32 {
            return Err(InviteError::InvalidField {
                field: "queue".into(),
                reason: format!("expected 32 bytes, got {}", queue_bytes.len()),
            });
        }

        let display_name = params.get("name").cloned();

        Ok(InvitePayload {
            account_id,
            public_key_b58,
            queue_id_b58,
            display_name,
            version,
        })
    }

    /// Encode the invitation as compact binary data suitable for QR codes.
    ///
    /// QR codes get exponentially harder to scan as payload size increases,
    /// so we use raw binary instead of JSON/URI to keep the payload small.
    ///
    /// Wire format:
    /// ```text
    /// [1 byte version]
    /// [32 bytes public key]
    /// [32 bytes queue ID]
    /// [1 byte name length, 0 = no name]
    /// [0..255 bytes name UTF-8]
    /// ```
    ///
    /// Total: 66 bytes minimum (no name) to 321 bytes maximum (255-char name).
    /// A QR code can comfortably hold ~300 bytes in binary mode.
    pub fn to_qr_data(&self) -> Result<Vec<u8>, InviteError> {
        let key_bytes = bs58::decode(&self.public_key_b58).into_vec().map_err(|e| {
            InviteError::InvalidField {
                field: "key".into(),
                reason: format!("invalid base58: {e}"),
            }
        })?;

        let queue_bytes =
            bs58::decode(&self.queue_id_b58)
                .into_vec()
                .map_err(|e| InviteError::InvalidField {
                    field: "queue".into(),
                    reason: format!("invalid base58: {e}"),
                })?;

        let name_bytes = self
            .display_name
            .as_ref()
            .map(|n| n.as_bytes())
            .unwrap_or(&[]);

        if name_bytes.len() > 255 {
            return Err(InviteError::InvalidField {
                field: "name".into(),
                reason: "display name too long for QR (max 255 bytes)".into(),
            });
        }

        let mut buf = Vec::with_capacity(66 + name_bytes.len());
        buf.push(self.version);
        buf.extend_from_slice(&key_bytes);
        buf.extend_from_slice(&queue_bytes);
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);

        Ok(buf)
    }

    /// Parse an invitation from compact binary QR data.
    ///
    /// Re-derives the Account ID from the embedded public key — this means
    /// the Account ID is never transmitted in the QR code, saving space and
    /// ensuring consistency (a tampered key will produce a different Account ID).
    pub fn from_qr_data(data: &[u8]) -> Result<Self, InviteError> {
        // Minimum: 1 (version) + 32 (key) + 32 (queue) + 1 (name len) = 66
        if data.len() < 66 {
            return Err(InviteError::MalformedBinary(format!(
                "too short: need at least 66 bytes, got {}",
                data.len()
            )));
        }

        let version = data[0];
        if version != INVITE_VERSION {
            return Err(InviteError::UnsupportedVersion(version));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[1..33]);

        let mut queue_bytes = [0u8; 32];
        queue_bytes.copy_from_slice(&data[33..65]);

        let name_len = data[65] as usize;
        if data.len() < 66 + name_len {
            return Err(InviteError::MalformedBinary(format!(
                "name length says {} bytes but only {} available",
                name_len,
                data.len() - 66
            )));
        }

        let display_name = if name_len > 0 {
            let name_str = std::str::from_utf8(&data[66..66 + name_len])
                .map_err(|e| InviteError::MalformedBinary(format!("invalid UTF-8 in name: {e}")))?;
            Some(name_str.to_string())
        } else {
            None
        };

        // Re-derive account ID from the key bytes (not transmitted in QR)
        let hash = Sha256::digest(key_bytes);
        let account_id = format!("{}{}", ACCOUNT_ID_PREFIX, bs58::encode(hash).into_string());

        let public_key_b58 = bs58::encode(&key_bytes).into_string();
        let queue_id_b58 = bs58::encode(&queue_bytes).into_string();

        Ok(InvitePayload {
            account_id,
            public_key_b58,
            queue_id_b58,
            display_name,
            version,
        })
    }

    /// Validate that the Account ID matches the public key.
    ///
    /// This catches tampering: if someone modifies the public key in a
    /// shared invitation link (e.g. MITM attack on the QR display), the
    /// re-derived Account ID won't match the one in the invite.
    ///
    /// Returns `Ok(())` if valid, or `Err(AccountIdMismatch)` if the
    /// Account ID doesn't match what the public key produces.
    pub fn validate(&self) -> Result<(), InviteError> {
        // Decode the public key from base58
        let key_bytes = bs58::decode(&self.public_key_b58).into_vec().map_err(|e| {
            InviteError::InvalidField {
                field: "key".into(),
                reason: format!("invalid base58: {e}"),
            }
        })?;

        if key_bytes.len() != 32 {
            return Err(InviteError::InvalidField {
                field: "key".into(),
                reason: format!("expected 32 bytes, got {}", key_bytes.len()),
            });
        }

        // Re-derive the account ID from the raw public key
        let hash = Sha256::digest(&key_bytes);
        let expected = format!("{}{}", ACCOUNT_ID_PREFIX, bs58::encode(hash).into_string());

        if self.account_id != expected {
            return Err(InviteError::AccountIdMismatch {
                expected,
                actual: self.account_id.clone(),
            });
        }

        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────

    /// Minimal percent-encoding for URI query values.
    /// Encodes spaces, ampersands, equals signs, and other URI-unsafe characters.
    fn uri_encode(s: &str) -> String {
        let mut encoded = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                // Unreserved characters (RFC 3986 §2.3)
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(b as char);
                }
                _ => {
                    encoded.push_str(&format!("%{:02X}", b));
                }
            }
        }
        encoded
    }

    /// Minimal percent-decoding for URI query values.
    fn uri_decode(s: &str) -> String {
        let mut decoded = Vec::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(val) =
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    decoded.push(val);
                    i += 3;
                    continue;
                }
            }
            decoded.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&decoded).into_owned()
    }

    /// Parse a URI query string into key-value pairs.
    /// Values are percent-decoded.
    fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
        query
            .split('&')
            .filter_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                Some((key.to_string(), Self::uri_decode(value)))
            })
            .collect()
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an invite with known key/queue bytes.
    fn make_test_invite(name: Option<&str>) -> InvitePayload {
        let key = [42u8; 32];
        let queue = [99u8; 32];
        InvitePayload::new(&key, &queue, name.map(String::from))
    }

    // -- Construction and validation --

    #[test]
    fn new_invite_has_correct_account_id() {
        let key = [42u8; 32];
        let queue = [99u8; 32];
        let invite = InvitePayload::new(&key, &queue, None);

        // Manually derive the expected account ID
        let hash = Sha256::digest(&key);
        let expected = format!("sb_{}", bs58::encode(hash).into_string());
        assert_eq!(invite.account_id, expected);
    }

    #[test]
    fn validate_passes_for_correct_invite() {
        let invite = make_test_invite(None);
        assert!(invite.validate().is_ok());
    }

    #[test]
    fn validate_fails_for_tampered_key() {
        let mut invite = make_test_invite(None);
        // Tamper with the public key
        invite.public_key_b58 = bs58::encode([0u8; 32]).into_string();
        let result = invite.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::AccountIdMismatch { .. } => {} // expected
            other => panic!("expected AccountIdMismatch, got: {other}"),
        }
    }

    #[test]
    fn validate_fails_for_tampered_account_id() {
        let mut invite = make_test_invite(None);
        invite.account_id = "sb_TAMPERED".to_string();
        let result = invite.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::AccountIdMismatch { .. } => {}
            other => panic!("expected AccountIdMismatch, got: {other}"),
        }
    }

    // -- URI round-trip --

    #[test]
    fn uri_round_trip_without_name() {
        let invite = make_test_invite(None);
        let uri = invite.to_uri();

        assert!(uri.starts_with("sofamsg://connect?"));
        assert!(uri.contains("v=1"));
        assert!(uri.contains("key="));
        assert!(uri.contains("queue="));
        assert!(!uri.contains("name="));

        let parsed = InvitePayload::from_uri(&uri).unwrap();
        assert_eq!(parsed.account_id, invite.account_id);
        assert_eq!(parsed.public_key_b58, invite.public_key_b58);
        assert_eq!(parsed.queue_id_b58, invite.queue_id_b58);
        assert_eq!(parsed.display_name, None);
        assert_eq!(parsed.version, INVITE_VERSION);
    }

    #[test]
    fn uri_round_trip_with_name() {
        let invite = make_test_invite(Some("Alice"));
        let uri = invite.to_uri();

        assert!(uri.contains("name=Alice"));

        let parsed = InvitePayload::from_uri(&uri).unwrap();
        assert_eq!(parsed.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn uri_round_trip_with_special_chars_in_name() {
        let invite = make_test_invite(Some("Alice & Bob = Friends!"));
        let uri = invite.to_uri();

        // Should be percent-encoded in the URI
        assert!(!uri.contains(" & "));
        assert!(uri.contains("%20"));

        let parsed = InvitePayload::from_uri(&uri).unwrap();
        assert_eq!(
            parsed.display_name,
            Some("Alice & Bob = Friends!".to_string())
        );
    }

    #[test]
    fn uri_rejects_wrong_scheme() {
        let result = InvitePayload::from_uri("https://connect?v=1&key=abc&queue=def");
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::InvalidScheme(s) => assert_eq!(s, "https"),
            other => panic!("expected InvalidScheme, got: {other}"),
        }
    }

    #[test]
    fn uri_rejects_wrong_host() {
        let invite = make_test_invite(None);
        let uri = invite.to_uri().replace("connect", "wrong");
        let result = InvitePayload::from_uri(&uri);
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::InvalidHost(h) => assert_eq!(h, "wrong"),
            other => panic!("expected InvalidHost, got: {other}"),
        }
    }

    #[test]
    fn uri_rejects_missing_key() {
        let result = InvitePayload::from_uri("sofamsg://connect?v=1&id=sb_abc&queue=def");
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::MissingField(f) => assert!(f.contains("key")),
            other => panic!("expected MissingField, got: {other}"),
        }
    }

    #[test]
    fn uri_rejects_missing_version() {
        let result = InvitePayload::from_uri("sofamsg://connect?key=abc&queue=def&id=sb_abc");
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::MissingField(f) => assert!(f.contains("v")),
            other => panic!("expected MissingField, got: {other}"),
        }
    }

    #[test]
    fn uri_rejects_invalid_key_length() {
        // base58 of 16 bytes instead of 32
        let short_key = bs58::encode([0u8; 16]).into_string();
        let queue = bs58::encode([0u8; 32]).into_string();
        let uri = format!(
            "sofamsg://connect?v=1&id=sb_test&key={}&queue={}",
            short_key, queue
        );
        let result = InvitePayload::from_uri(&uri);
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::InvalidField { field, reason } => {
                assert_eq!(field, "key");
                assert!(reason.contains("32"));
            }
            other => panic!("expected InvalidField, got: {other}"),
        }
    }

    #[test]
    fn uri_rejects_unsupported_version() {
        let invite = make_test_invite(None);
        let uri = invite.to_uri().replace("v=1", "v=99");
        let result = InvitePayload::from_uri(&uri);
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::UnsupportedVersion(v) => assert_eq!(v, 99),
            other => panic!("expected UnsupportedVersion, got: {other}"),
        }
    }

    // -- QR binary round-trip --

    #[test]
    fn qr_round_trip_without_name() {
        let invite = make_test_invite(None);
        let qr = invite.to_qr_data().unwrap();

        // 1 (version) + 32 (key) + 32 (queue) + 1 (name_len=0) = 66
        assert_eq!(qr.len(), 66);

        let parsed = InvitePayload::from_qr_data(&qr).unwrap();
        assert_eq!(parsed.public_key_b58, invite.public_key_b58);
        assert_eq!(parsed.queue_id_b58, invite.queue_id_b58);
        assert_eq!(parsed.display_name, None);
        // Account ID is re-derived in from_qr_data, so it should match
        assert_eq!(parsed.account_id, invite.account_id);
    }

    #[test]
    fn qr_round_trip_with_name() {
        let invite = make_test_invite(Some("Bob"));
        let qr = invite.to_qr_data().unwrap();

        // 66 + 3 bytes for "Bob"
        assert_eq!(qr.len(), 69);

        let parsed = InvitePayload::from_qr_data(&qr).unwrap();
        assert_eq!(parsed.display_name, Some("Bob".to_string()));
    }

    #[test]
    fn qr_round_trip_with_unicode_name() {
        let invite = make_test_invite(Some("Álice 🔐"));
        let qr = invite.to_qr_data().unwrap();
        let parsed = InvitePayload::from_qr_data(&qr).unwrap();
        assert_eq!(parsed.display_name, Some("Álice 🔐".to_string()));
    }

    #[test]
    fn qr_rejects_too_short() {
        let short = vec![0u8; 30];
        let result = InvitePayload::from_qr_data(&short);
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::MalformedBinary(msg) => assert!(msg.contains("too short")),
            other => panic!("expected MalformedBinary, got: {other}"),
        }
    }

    #[test]
    fn qr_rejects_unsupported_version() {
        let mut data = vec![99u8]; // bad version
        data.extend_from_slice(&[0u8; 65]); // key + queue + name_len
        let result = InvitePayload::from_qr_data(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::UnsupportedVersion(v) => assert_eq!(v, 99),
            other => panic!("expected UnsupportedVersion, got: {other}"),
        }
    }

    #[test]
    fn qr_rejects_truncated_name() {
        let invite = make_test_invite(Some("Hello"));
        let mut qr = invite.to_qr_data().unwrap();
        // Truncate the name data (remove last 2 bytes)
        qr.truncate(qr.len() - 2);
        let result = InvitePayload::from_qr_data(&qr);
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::MalformedBinary(msg) => {
                assert!(msg.contains("name length"));
            }
            other => panic!("expected MalformedBinary, got: {other}"),
        }
    }

    #[test]
    fn qr_rejects_name_too_long() {
        let long_name = "A".repeat(256);
        let invite = make_test_invite(Some(&long_name));
        let result = invite.to_qr_data();
        assert!(result.is_err());
        match result.unwrap_err() {
            InviteError::InvalidField { field, reason } => {
                assert_eq!(field, "name");
                assert!(reason.contains("too long"));
            }
            other => panic!("expected InvalidField, got: {other}"),
        }
    }

    #[test]
    fn qr_account_id_is_rederived_not_transmitted() {
        let key = [42u8; 32];
        let queue = [99u8; 32];
        let invite = InvitePayload::new(&key, &queue, None);
        let qr = invite.to_qr_data().unwrap();

        // The account ID is NOT in the binary data — it's re-derived
        // when parsing. Verify by checking the binary doesn't contain "sb_".
        let qr_str = String::from_utf8_lossy(&qr);
        assert!(
            !qr_str.contains("sb_"),
            "QR data should not contain the account ID string"
        );

        // But the parsed invite should have the correct account ID
        let parsed = InvitePayload::from_qr_data(&qr).unwrap();
        assert_eq!(parsed.account_id, invite.account_id);
        assert!(parsed.validate().is_ok());
    }

    // -- Cross-format consistency --

    #[test]
    fn uri_and_qr_produce_same_invite() {
        let invite = make_test_invite(Some("Carol"));

        // Round-trip through URI
        let via_uri = InvitePayload::from_uri(&invite.to_uri()).unwrap();
        // Round-trip through QR
        let via_qr = InvitePayload::from_qr_data(&invite.to_qr_data().unwrap()).unwrap();

        assert_eq!(via_uri.public_key_b58, via_qr.public_key_b58);
        assert_eq!(via_uri.queue_id_b58, via_qr.queue_id_b58);
        assert_eq!(via_uri.display_name, via_qr.display_name);
        assert_eq!(via_uri.version, via_qr.version);

        // Both should validate
        assert!(via_uri.validate().is_ok());
        assert!(via_qr.validate().is_ok());
    }

    // -- URI encoding/decoding --

    #[test]
    fn uri_encode_preserves_safe_chars() {
        let safe = "abcABC012-_.~";
        assert_eq!(InvitePayload::uri_encode(safe), safe);
    }

    #[test]
    fn uri_encode_encodes_unsafe_chars() {
        assert_eq!(InvitePayload::uri_encode("a b"), "a%20b");
        assert_eq!(InvitePayload::uri_encode("a&b"), "a%26b");
        assert_eq!(InvitePayload::uri_encode("a=b"), "a%3Db");
    }

    #[test]
    fn uri_decode_round_trips() {
        let original = "Hello, World! #$%^&*()=+";
        let encoded = InvitePayload::uri_encode(original);
        let decoded = InvitePayload::uri_decode(&encoded);
        assert_eq!(decoded, original);
    }

    // -- Edge cases --

    #[test]
    fn invite_with_max_length_name() {
        let name = "A".repeat(255);
        let invite = make_test_invite(Some(&name));

        // QR should work with exactly 255 chars
        let qr = invite.to_qr_data().unwrap();
        let parsed = InvitePayload::from_qr_data(&qr).unwrap();
        assert_eq!(parsed.display_name, Some(name));

        // URI should also work
        let uri = invite.to_uri();
        let parsed2 = InvitePayload::from_uri(&uri).unwrap();
        assert_eq!(parsed2.display_name, invite.display_name);
    }

    #[test]
    fn invite_version_is_1() {
        let invite = make_test_invite(None);
        assert_eq!(invite.version, 1);
    }
}

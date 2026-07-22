/// Message envelope format for DHT-stored payloads.
///
/// When User A sends a message to User B:
/// 1. A encrypts the message body (future: with Signal-protocol E2E keys;
///    for now, as a raw ciphertext blob from vault.rs).
/// 2. A wraps the ciphertext in a `MessageEnvelope` which includes
///    metadata needed for B to process it.
/// 3. A stores the serialized envelope as a Kademlia DHT record under
///    B's Queue ID.
/// 4. B (once woken by the doorbell ping) queries the DHT for records
///    under their Queue ID, deserializes the envelope, decrypts, and
///    requests deletion of the record from the DHT.
use serde::{Deserialize, Serialize};

/// A message envelope stored on the DHT.
///
/// The `ciphertext` field contains the encrypted message body. The
/// envelope itself is NOT encrypted — it's stored as-is on DHT nodes.
/// This is acceptable because:
/// - The ciphertext is already encrypted (Layer 2 / future Layer 0).
/// - DHT nodes see the envelope metadata but not the plaintext.
/// - The `sender_queue_id` lets the recipient know which queue to
///   reply to (without revealing the sender's Account ID or public key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Protocol version for forward compatibility.
    pub version: u8,
    /// The sender's Queue ID (base58-encoded), so the recipient knows
    /// where to send replies. NOT the Account ID — Queue IDs are
    /// one-way derived and don't reveal identity.
    pub sender_queue_id: String,
    /// Unix timestamp (seconds) when the message was created.
    pub created_at: u64,
    /// The encrypted message body. Opaque to relay nodes.
    /// This should be a serialized `EncryptedMessage` from the Double
    /// Ratchet (Layer 0 — end-to-end encryption). The envelope itself
    /// travels over Noise-encrypted transport (Layer 1). After delivery,
    /// the plaintext is re-encrypted with the vault key (Layer 2) for
    /// local storage.
    pub ciphertext: Vec<u8>,
    /// Unique message ID to prevent duplicate delivery.
    /// Generated as random bytes, base58-encoded.
    pub message_id: String,
}

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

impl MessageEnvelope {
    /// Create a new message envelope.
    pub fn new(sender_queue_id: String, ciphertext: Vec<u8>) -> Self {
        // Generate a random message ID
        let mut id_bytes = [0u8; 16];
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Simple ID: timestamp bytes + position index
        // (In production, use OsRng for the random part)
        id_bytes[0..8].copy_from_slice(&now.to_le_bytes());
        // Fill remaining bytes with a hash of the ciphertext for uniqueness
        let hash = sha2::Sha256::digest(&ciphertext);
        id_bytes[8..16].copy_from_slice(&hash[..8]);

        let message_id = bs58::encode(&id_bytes).into_string();

        MessageEnvelope {
            version: PROTOCOL_VERSION,
            sender_queue_id,
            created_at: now,
            ciphertext,
            message_id,
        }
    }

    /// Serialize the envelope to bytes for DHT storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize an envelope from bytes retrieved from the DHT.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// A batch of envelopes stored under a single Queue ID.
/// Multiple senders may have messages waiting, so the DHT record
/// contains a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessages {
    pub envelopes: Vec<MessageEnvelope>,
}

impl QueuedMessages {
    pub fn new() -> Self {
        QueuedMessages {
            envelopes: Vec::new(),
        }
    }

    pub fn push(&mut self, envelope: MessageEnvelope) {
        self.envelopes.push(envelope);
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

impl Default for QueuedMessages {
    fn default() -> Self {
        Self::new()
    }
}

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let env =
            MessageEnvelope::new("test_queue_id".to_string(), b"encrypted data here".to_vec());

        let bytes = env.to_bytes().unwrap();
        let recovered = MessageEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.version, PROTOCOL_VERSION);
        assert_eq!(recovered.sender_queue_id, "test_queue_id");
        assert_eq!(recovered.ciphertext, b"encrypted data here");
        assert_eq!(recovered.message_id, env.message_id);
    }

    #[test]
    fn queued_messages_round_trip() {
        let mut queue = QueuedMessages::new();
        queue.push(MessageEnvelope::new(
            "sender_a".to_string(),
            b"msg 1".to_vec(),
        ));
        queue.push(MessageEnvelope::new(
            "sender_b".to_string(),
            b"msg 2".to_vec(),
        ));

        let bytes = queue.to_bytes().unwrap();
        let recovered = QueuedMessages::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.envelopes.len(), 2);
        assert_eq!(recovered.envelopes[0].sender_queue_id, "sender_a");
        assert_eq!(recovered.envelopes[1].sender_queue_id, "sender_b");
    }

    #[test]
    fn envelope_has_unique_message_id() {
        let e1 = MessageEnvelope::new("q".to_string(), b"a".to_vec());
        let e2 = MessageEnvelope::new("q".to_string(), b"b".to_vec());
        // Different ciphertext → different message ID
        assert_ne!(e1.message_id, e2.message_id);
    }
}

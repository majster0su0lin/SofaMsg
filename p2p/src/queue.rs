/// Queue ID derivation and management.
///
/// A Queue ID is a deterministic identifier derived from a user's public
/// key. It serves as the DHT key under which messages destined for that
/// user are stored. The derivation is one-way: knowing a Queue ID does
/// not reveal the public key or Account ID it was derived from.
///
/// Queue ID = base58( SHA-256( public_key_bytes || "sofamsg_queue_v1" ) )
///
/// The domain separator ("sofamsg_queue_v1") ensures Queue IDs are
/// distinct from Account IDs (which use a bare SHA-256 of the public key).
use sha2::{Digest, Sha256};

/// A Queue ID used as a DHT key for message storage and retrieval.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueueId {
    /// Raw 32-byte hash.
    bytes: [u8; 32],
    /// Human-readable base58 representation.
    encoded: String,
}

/// Domain separator to prevent Queue IDs from colliding with Account IDs
/// (which are also SHA-256 hashes of the public key, but without this suffix).
const QUEUE_DOMAIN_SEPARATOR: &[u8] = b"sofamsg_queue_v1";

impl QueueId {
    /// Derive a Queue ID from a 32-byte Ed25519 public key.
    pub fn from_public_key(public_key_bytes: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key_bytes);
        hasher.update(QUEUE_DOMAIN_SEPARATOR);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);

        let encoded = bs58::encode(&bytes).into_string();

        QueueId { bytes, encoded }
    }

    /// Get the raw 32-byte hash (for use as a DHT key).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get the base58-encoded string representation.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Convert to a libp2p Kademlia record key.
    pub fn to_kad_key(&self) -> libp2p::kad::RecordKey {
        libp2p::kad::RecordKey::new(&self.bytes)
    }
}

impl std::fmt::Display for QueueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_same_key() {
        let key = [42u8; 32];
        let q1 = QueueId::from_public_key(&key);
        let q2 = QueueId::from_public_key(&key);
        assert_eq!(q1, q2);
        assert_eq!(q1.as_str(), q2.as_str());
    }

    #[test]
    fn different_keys_different_queues() {
        let q1 = QueueId::from_public_key(&[1u8; 32]);
        let q2 = QueueId::from_public_key(&[2u8; 32]);
        assert_ne!(q1, q2);
    }

    #[test]
    fn queue_id_differs_from_account_id() {
        // Account ID = bs58(SHA-256(pubkey))
        // Queue ID  = bs58(SHA-256(pubkey || domain_separator))
        // They MUST differ.
        let pubkey = [99u8; 32];

        let account_hash = Sha256::digest(&pubkey);
        let account_id = bs58::encode(account_hash).into_string();

        let queue = QueueId::from_public_key(&pubkey);

        assert_ne!(
            account_id,
            queue.as_str(),
            "Queue ID must differ from Account ID due to domain separator"
        );
    }

    #[test]
    fn bytes_are_32_bytes() {
        let q = QueueId::from_public_key(&[0u8; 32]);
        assert_eq!(q.as_bytes().len(), 32);
    }
}

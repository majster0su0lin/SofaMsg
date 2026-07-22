use crate::protocol::MessageEnvelope;
use crate::queue::QueueId;
/// High-level messaging integration — ties E2E encryption into the P2P message flow.
///
/// This module provides the glue between:
/// - **Layer 0** (E2E encryption via Double Ratchet in `silentbell_core::e2e`)
/// - **Layer 1** (transport via libp2p Noise — handled by `node.rs`)
/// - **Layer 2** (at-rest vault encryption in `silentbell_core::vault`)
///
/// # Message sending flow
///
/// ```text
/// plaintext
///   → E2E encrypt (Double Ratchet, Layer 0)
///     → serialize EncryptedMessage to bytes
///       → wrap in MessageEnvelope
///         → store on DHT via SofaNode (travels over Noise, Layer 1)
/// ```
///
/// # Message receiving flow
///
/// ```text
/// DHT record (arrived over Noise, Layer 1)
///   → deserialize MessageEnvelope
///     → deserialize EncryptedMessage from envelope.ciphertext
///       → E2E decrypt (Double Ratchet, Layer 0)
///         → store plaintext in local DB (vault-encrypted DB, Layer 2)
/// ```
use silentbell_core::e2e::{EncryptedMessage, SessionManager};

/// Encrypt a plaintext message using the E2E session and wrap it in
/// a `MessageEnvelope` ready for DHT storage.
///
/// # Arguments
///
/// * `session_mgr` — The session manager holding E2E sessions
/// * `peer_id` — The recipient's Ed25519 public key bytes (session key)
/// * `our_queue_id` — Our Queue ID (included so the recipient can reply)
/// * `plaintext` — The message content to encrypt
///
/// # Errors
///
/// Returns `Err` if no E2E session exists for the given peer, or if
/// serialization fails.
pub fn prepare_outgoing_message(
    session_mgr: &mut SessionManager,
    peer_id: &[u8; 32],
    our_queue_id: &QueueId,
    plaintext: &[u8],
) -> Result<MessageEnvelope, String> {
    // Step 1: E2E encrypt with Double Ratchet (Layer 0)
    let encrypted: EncryptedMessage = session_mgr
        .encrypt(peer_id, plaintext)
        .map_err(|e| e.to_string())?;

    // Step 2: Serialize the EncryptedMessage to bytes
    let ciphertext = serde_json::to_vec(&encrypted)
        .map_err(|e| format!("Failed to serialize EncryptedMessage: {e}"))?;

    // Step 3: Wrap in a MessageEnvelope for DHT storage
    let envelope = MessageEnvelope::new(our_queue_id.as_str().to_string(), ciphertext);

    Ok(envelope)
}

/// Extract and decrypt a message from a received `MessageEnvelope`
/// using the E2E session.
///
/// # Arguments
///
/// * `session_mgr` — The session manager holding E2E sessions
/// * `peer_id` — The sender's Ed25519 public key bytes (session key)
/// * `envelope` — The received message envelope from the DHT
///
/// # Returns
///
/// The decrypted plaintext bytes on success.
///
/// # Errors
///
/// Returns `Err` if deserialization fails, no session exists, or
/// GCM authentication fails (message was tampered with).
pub fn process_incoming_message(
    session_mgr: &mut SessionManager,
    peer_id: &[u8; 32],
    envelope: &MessageEnvelope,
) -> Result<Vec<u8>, String> {
    // Step 1: Deserialize the EncryptedMessage from envelope.ciphertext
    let encrypted: EncryptedMessage = serde_json::from_slice(&envelope.ciphertext)
        .map_err(|e| format!("Failed to deserialize EncryptedMessage: {e}"))?;

    // Step 2: E2E decrypt with Double Ratchet (Layer 0)
    let plaintext = session_mgr
        .decrypt(peer_id, &encrypted)
        .map_err(|e| e.to_string())?;

    Ok(plaintext)
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use silentbell_core::e2e::{
        generate_one_time_prekey, generate_signed_prekey, PreKeyBundle, SessionManager,
    };

    /// Helper: set up Alice and Bob with completed E2E handshake.
    fn setup_e2e_pair() -> (
        SessionManager,
        SessionManager,
        [u8; 32],
        [u8; 32], // peer IDs
        QueueId,
        QueueId, // queue IDs
    ) {
        let alice_signing = SigningKey::generate(&mut OsRng);
        let bob_signing = SigningKey::generate(&mut OsRng);

        let bob_spk = generate_signed_prekey(&bob_signing);
        let bob_opk = generate_one_time_prekey();

        let bob_bundle = PreKeyBundle {
            identity_key: bob_signing.verifying_key(),
            signed_prekey_public: bob_spk.public,
            signed_prekey_signature: bob_spk.signature,
            one_time_prekey_public: Some(bob_opk.public),
        };

        let mut alice_mgr = SessionManager::new(alice_signing.clone());
        let mut bob_mgr = SessionManager::new(bob_signing.clone());

        let ek = alice_mgr.create_outgoing_session(&bob_bundle).unwrap();
        bob_mgr.create_incoming_session(
            &alice_signing.verifying_key(),
            &ek,
            &bob_spk,
            Some(&bob_opk),
        );

        let bob_peer_id = bob_signing.verifying_key().to_bytes();
        let alice_peer_id = alice_signing.verifying_key().to_bytes();

        let alice_queue = QueueId::from_public_key(&alice_signing.verifying_key().to_bytes());
        let bob_queue = QueueId::from_public_key(&bob_signing.verifying_key().to_bytes());

        (
            alice_mgr,
            bob_mgr,
            bob_peer_id,
            alice_peer_id,
            alice_queue,
            bob_queue,
        )
    }

    #[test]
    fn full_e2e_message_flow_through_envelope() {
        let (mut alice_mgr, mut bob_mgr, bob_peer_id, alice_peer_id, alice_queue, _bob_queue) =
            setup_e2e_pair();

        // Alice sends a message
        let envelope = prepare_outgoing_message(
            &mut alice_mgr,
            &bob_peer_id,
            &alice_queue,
            b"Hello Bob, this is E2E encrypted!",
        )
        .expect("prepare should succeed");

        // Verify envelope structure
        assert_eq!(envelope.sender_queue_id, alice_queue.as_str());
        assert!(!envelope.ciphertext.is_empty());
        assert!(!envelope.message_id.is_empty());

        // Bob receives and decrypts
        let plaintext = process_incoming_message(&mut bob_mgr, &alice_peer_id, &envelope)
            .expect("process should succeed");

        assert_eq!(plaintext, b"Hello Bob, this is E2E encrypted!");
    }

    #[test]
    fn bidirectional_e2e_through_envelopes() {
        let (mut alice_mgr, mut bob_mgr, bob_peer_id, alice_peer_id, alice_queue, bob_queue) =
            setup_e2e_pair();

        // Alice → Bob
        let env1 = prepare_outgoing_message(&mut alice_mgr, &bob_peer_id, &alice_queue, b"Hey Bob")
            .unwrap();
        let pt1 = process_incoming_message(&mut bob_mgr, &alice_peer_id, &env1).unwrap();
        assert_eq!(pt1, b"Hey Bob");

        // Bob → Alice
        let env2 = prepare_outgoing_message(&mut bob_mgr, &alice_peer_id, &bob_queue, b"Hey Alice")
            .unwrap();
        let pt2 = process_incoming_message(&mut alice_mgr, &bob_peer_id, &env2).unwrap();
        assert_eq!(pt2, b"Hey Alice");

        // Alice → Bob again (post-ratchet)
        let env3 = prepare_outgoing_message(
            &mut alice_mgr,
            &bob_peer_id,
            &alice_queue,
            b"E2E ratchet works!",
        )
        .unwrap();
        let pt3 = process_incoming_message(&mut bob_mgr, &alice_peer_id, &env3).unwrap();
        assert_eq!(pt3, b"E2E ratchet works!");
    }

    #[test]
    fn envelope_ciphertext_is_not_plaintext() {
        let (mut alice_mgr, _, bob_peer_id, _, alice_queue, _) = setup_e2e_pair();

        let plaintext = b"secret message";
        let envelope =
            prepare_outgoing_message(&mut alice_mgr, &bob_peer_id, &alice_queue, plaintext)
                .unwrap();

        // The envelope's ciphertext must NOT contain the plaintext
        let ciphertext_str = String::from_utf8_lossy(&envelope.ciphertext);
        assert!(
            !ciphertext_str.contains("secret message"),
            "Plaintext must not appear in the envelope ciphertext"
        );
    }

    #[test]
    fn no_session_returns_error() {
        let alice_signing = SigningKey::generate(&mut OsRng);
        let mut alice_mgr = SessionManager::new(alice_signing.clone());
        let fake_peer = [0xAB; 32];
        let queue = QueueId::from_public_key(&alice_signing.verifying_key().to_bytes());

        let result = prepare_outgoing_message(&mut alice_mgr, &fake_peer, &queue, b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_envelope_is_rejected() {
        let (mut alice_mgr, mut bob_mgr, bob_peer_id, alice_peer_id, alice_queue, _) =
            setup_e2e_pair();

        let mut envelope =
            prepare_outgoing_message(&mut alice_mgr, &bob_peer_id, &alice_queue, b"tamper test")
                .unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = envelope.ciphertext.get_mut(10) {
            *byte ^= 0xFF;
        }

        let result = process_incoming_message(&mut bob_mgr, &alice_peer_id, &envelope);
        assert!(result.is_err(), "Tampered message must be rejected");
    }

    #[test]
    fn multiple_messages_each_unique() {
        let (mut alice_mgr, _, bob_peer_id, _, alice_queue, _) = setup_e2e_pair();

        let env1 =
            prepare_outgoing_message(&mut alice_mgr, &bob_peer_id, &alice_queue, b"same text")
                .unwrap();
        let env2 =
            prepare_outgoing_message(&mut alice_mgr, &bob_peer_id, &alice_queue, b"same text")
                .unwrap();

        // Even identical plaintext must produce different ciphertext
        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.message_id, env2.message_id);
    }
}

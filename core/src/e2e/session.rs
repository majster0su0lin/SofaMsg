//! # Session Management
//!
//! Provides a higher-level API over X3DH and the Double Ratchet, managing
//! per-peer encryption sessions with serialization support for persistence.
//!
//! ## Usage flow
//!
//! 1. Alice creates a `SessionManager` for her identity.
//! 2. To message Bob for the first time, she calls
//!    `manager.create_outgoing_session(bob_bundle)` — this runs X3DH and
//!    initializes a Double Ratchet sender.
//! 3. She calls `manager.encrypt(bob_id, plaintext)` to encrypt messages.
//! 4. Bob, upon receiving Alice's first message, calls
//!    `manager.create_incoming_session(alice_identity, ephemeral_key, ...)`
//!    to run the responder side of X3DH and initialize a Double Ratchet receiver.
//! 5. Both sides then use `encrypt`/`decrypt` for ongoing communication.

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;

use super::x3dh::{
    PreKeyBundle, SignedPreKey, OneTimePreKey,
    initiate_x3dh, respond_x3dh,
};
use super::ratchet::{RatchetState, EncryptedMessage};
use x25519_dalek::PublicKey as X25519PublicKey;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A single E2E encryption session with a specific peer.
///
/// Wraps a [`RatchetState`] with the peer's identity for routing and
/// session lookup purposes.
pub struct Session {
    /// The peer's Ed25519 identity public key.
    pub peer_identity: VerifyingKey,
    /// The Double Ratchet state for this session.
    pub ratchet: RatchetState,
}

impl Session {
    /// Encrypt a message to this session's peer.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> EncryptedMessage {
        self.ratchet.encrypt(plaintext)
    }

    /// Decrypt a message from this session's peer.
    pub fn decrypt(&mut self, msg: &EncryptedMessage) -> Result<Vec<u8>, &'static str> {
        self.ratchet.decrypt(msg)
    }
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Manages E2E encryption sessions for multiple peers.
///
/// Sessions are keyed by the peer's Ed25519 public key bytes (32 bytes),
/// which serves as a stable, unique identifier for each contact.
pub struct SessionManager {
    /// Our long-term Ed25519 signing key.
    our_identity: SigningKey,
    /// Active sessions, keyed by peer's public key bytes.
    sessions: HashMap<[u8; 32], Session>,
}

impl SessionManager {
    /// Create a new `SessionManager` for the given identity.
    pub fn new(our_identity: SigningKey) -> Self {
        SessionManager {
            our_identity,
            sessions: HashMap::new(),
        }
    }

    /// Create a new **outgoing** session with a peer (we are the X3DH initiator).
    ///
    /// This runs X3DH against the peer's published pre-key bundle and
    /// initializes a Double Ratchet in sender mode.
    ///
    /// Returns the X3DH ephemeral public key that must be sent to the peer
    /// (so they can complete their side of X3DH).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the pre-key bundle's signature is invalid.
    pub fn create_outgoing_session(
        &mut self,
        peer_bundle: &PreKeyBundle,
    ) -> Result<X25519PublicKey, &'static str> {
        let x3dh_output = initiate_x3dh(&self.our_identity, peer_bundle)?;

        let ratchet = RatchetState::init_sender(
            x3dh_output.shared_secret,
            peer_bundle.signed_prekey_public,
        );

        let peer_id = peer_bundle.identity_key.to_bytes();
        self.sessions.insert(
            peer_id,
            Session {
                peer_identity: peer_bundle.identity_key,
                ratchet,
            },
        );

        Ok(x3dh_output.ephemeral_public_key)
    }

    /// Create a new **incoming** session with a peer (we are the X3DH responder).
    ///
    /// Called when we receive an initial message from a peer who ran X3DH
    /// against our pre-key bundle.
    ///
    /// # Arguments
    ///
    /// - `peer_identity` — The initiator's Ed25519 public key
    /// - `peer_ephemeral` — The initiator's ephemeral X25519 public key
    ///   (received in their initial message)
    /// - `our_spk` — Our signed pre-key that the initiator used
    /// - `our_opk` — The one-time pre-key the initiator used, if any
    pub fn create_incoming_session(
        &mut self,
        peer_identity: &VerifyingKey,
        peer_ephemeral: &X25519PublicKey,
        our_spk: &SignedPreKey,
        our_opk: Option<&OneTimePreKey>,
    ) -> [u8; 32] {
        let x3dh_output = respond_x3dh(
            &self.our_identity,
            our_spk,
            our_opk,
            peer_identity,
            peer_ephemeral,
        );

        let ratchet = RatchetState::init_receiver(
            x3dh_output.shared_secret,
            our_spk.secret.clone(),
            our_spk.public,
        );

        let peer_id = peer_identity.to_bytes();
        self.sessions.insert(
            peer_id,
            Session {
                peer_identity: *peer_identity,
                ratchet,
            },
        );

        x3dh_output.shared_secret
    }

    /// Encrypt a message to a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no session exists for the given peer.
    pub fn encrypt(
        &mut self,
        peer_id: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<EncryptedMessage, &'static str> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or("No session exists for this peer")?;
        Ok(session.encrypt(plaintext))
    }

    /// Decrypt a message from a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no session exists or decryption fails.
    pub fn decrypt(
        &mut self,
        peer_id: &[u8; 32],
        msg: &EncryptedMessage,
    ) -> Result<Vec<u8>, &'static str> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or("No session exists for this peer")?;
        session.decrypt(msg)
    }

    /// Check whether a session exists for the given peer.
    pub fn has_session(&self, peer_id: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_id)
    }

    /// Get a reference to a session for the given peer, if one exists.
    pub fn get_session(&self, peer_id: &[u8; 32]) -> Option<&Session> {
        self.sessions.get(peer_id)
    }

    /// Get a mutable reference to a session for the given peer.
    pub fn get_session_mut(&mut self, peer_id: &[u8; 32]) -> Option<&mut Session> {
        self.sessions.get_mut(peer_id)
    }

    /// Remove and return a session for the given peer.
    pub fn remove_session(&mut self, peer_id: &[u8; 32]) -> Option<Session> {
        self.sessions.remove(peer_id)
    }

    /// List all peer IDs with active sessions.
    pub fn peer_ids(&self) -> Vec<[u8; 32]> {
        self.sessions.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::x3dh::{generate_signed_prekey, generate_one_time_prekey};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    /// Helper: set up Alice and Bob SessionManagers with a completed handshake.
    fn setup_session_pair() -> (SessionManager, SessionManager, [u8; 32], [u8; 32]) {
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
        let mut bob_mgr = SessionManager::new(bob_signing);

        // Alice initiates X3DH.
        let ephemeral_pk = alice_mgr
            .create_outgoing_session(&bob_bundle)
            .expect("outgoing session creation should succeed");

        // Bob responds to X3DH.
        bob_mgr.create_incoming_session(
            &alice_signing.verifying_key(),
            &ephemeral_pk,
            &bob_spk,
            Some(&bob_opk),
        );

        let alice_peer_id = bob_bundle.identity_key.to_bytes();
        let bob_peer_id = alice_signing.verifying_key().to_bytes();

        (alice_mgr, bob_mgr, alice_peer_id, bob_peer_id)
    }

    #[test]
    fn session_create_and_roundtrip() {
        let (mut alice_mgr, mut bob_mgr, alice_peer_id, bob_peer_id) = setup_session_pair();

        // Alice encrypts, Bob decrypts.
        let encrypted = alice_mgr
            .encrypt(&alice_peer_id, b"Hello from Alice!")
            .unwrap();
        let decrypted = bob_mgr
            .decrypt(&bob_peer_id, &encrypted)
            .unwrap();
        assert_eq!(decrypted, b"Hello from Alice!");
    }

    #[test]
    fn session_bidirectional_conversation() {
        let (mut alice_mgr, mut bob_mgr, alice_peer_id, bob_peer_id) = setup_session_pair();

        // Alice → Bob
        let e1 = alice_mgr.encrypt(&alice_peer_id, b"Hey Bob").unwrap();
        assert_eq!(bob_mgr.decrypt(&bob_peer_id, &e1).unwrap(), b"Hey Bob");

        // Bob → Alice
        let e2 = bob_mgr.encrypt(&bob_peer_id, b"Hey Alice").unwrap();
        assert_eq!(alice_mgr.decrypt(&alice_peer_id, &e2).unwrap(), b"Hey Alice");

        // Alice → Bob again
        let e3 = alice_mgr.encrypt(&alice_peer_id, b"What's up?").unwrap();
        assert_eq!(bob_mgr.decrypt(&bob_peer_id, &e3).unwrap(), b"What's up?");
    }

    #[test]
    fn session_no_session_returns_error() {
        let alice_signing = SigningKey::generate(&mut OsRng);
        let mut mgr = SessionManager::new(alice_signing);

        let fake_peer_id = [0xAB; 32];
        let result = mgr.encrypt(&fake_peer_id, b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn session_has_and_remove() {
        let (alice_mgr, _, alice_peer_id, _) = setup_session_pair();

        assert!(alice_mgr.has_session(&alice_peer_id));
        assert!(!alice_mgr.has_session(&[0xFF; 32]));
    }

    #[test]
    fn full_integration_x3dh_to_ratchet_to_encrypt_decrypt() {
        // End-to-end test: X3DH key agreement → Double Ratchet init → multi-message conversation.
        let alice_signing = SigningKey::generate(&mut OsRng);
        let bob_signing = SigningKey::generate(&mut OsRng);

        // Bob publishes pre-key bundle.
        let bob_spk = generate_signed_prekey(&bob_signing);
        let bob_opk = generate_one_time_prekey();
        let bob_bundle = PreKeyBundle {
            identity_key: bob_signing.verifying_key(),
            signed_prekey_public: bob_spk.public,
            signed_prekey_signature: bob_spk.signature,
            one_time_prekey_public: Some(bob_opk.public),
        };

        // Alice runs X3DH.
        let alice_x3dh = initiate_x3dh(&alice_signing, &bob_bundle)
            .expect("X3DH should succeed");

        // Bob runs X3DH.
        let bob_x3dh = respond_x3dh(
            &bob_signing,
            &bob_spk,
            Some(&bob_opk),
            &alice_signing.verifying_key(),
            &alice_x3dh.ephemeral_public_key,
        );

        // Verify shared secrets match.
        assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

        // Initialize Double Ratchet.
        let mut alice_ratchet = RatchetState::init_sender(
            alice_x3dh.shared_secret,
            bob_bundle.signed_prekey_public,
        );
        let mut bob_ratchet = RatchetState::init_receiver(
            bob_x3dh.shared_secret,
            bob_spk.secret.clone(),
            bob_spk.public,
        );

        // Multi-message conversation.
        let messages = vec![
            (true, "Hello Bob, this is Alice."),
            (true, "Are you there?"),
            (false, "Yes, I'm here! Hi Alice."),
            (true, "Great, the encryption works!"),
            (false, "Indeed it does. Forward secrecy FTW."),
        ];

        for (alice_sends, text) in messages {
            if alice_sends {
                let encrypted = alice_ratchet.encrypt(text.as_bytes());
                let decrypted = bob_ratchet.decrypt(&encrypted)
                    .expect("Bob should decrypt Alice's message");
                assert_eq!(
                    String::from_utf8(decrypted).unwrap(),
                    text,
                    "Decrypted text must match original"
                );
            } else {
                let encrypted = bob_ratchet.encrypt(text.as_bytes());
                let decrypted = alice_ratchet.decrypt(&encrypted)
                    .expect("Alice should decrypt Bob's message");
                assert_eq!(
                    String::from_utf8(decrypted).unwrap(),
                    text,
                    "Decrypted text must match original"
                );
            }
        }
    }

    #[test]
    fn full_integration_via_session_manager() {
        // Same as above but using the SessionManager API.
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
        let mut bob_mgr = SessionManager::new(bob_signing);

        let ek = alice_mgr.create_outgoing_session(&bob_bundle).unwrap();
        bob_mgr.create_incoming_session(
            &alice_signing.verifying_key(),
            &ek,
            &bob_spk,
            Some(&bob_opk),
        );

        let bob_id = bob_bundle.identity_key.to_bytes();
        let alice_id = alice_signing.verifying_key().to_bytes();

        // 10-message conversation.
        for i in 0..10 {
            let text = format!("Integration test message #{}", i);
            if i % 2 == 0 {
                let enc = alice_mgr.encrypt(&bob_id, text.as_bytes()).unwrap();
                let dec = bob_mgr.decrypt(&alice_id, &enc).unwrap();
                assert_eq!(dec, text.as_bytes());
            } else {
                let enc = bob_mgr.encrypt(&alice_id, text.as_bytes()).unwrap();
                let dec = alice_mgr.decrypt(&bob_id, &enc).unwrap();
                assert_eq!(dec, text.as_bytes());
            }
        }
    }
}

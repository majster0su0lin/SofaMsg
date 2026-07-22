//! # Double Ratchet Algorithm
//!
//! Implements the [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
//! for per-message forward secrecy and future secrecy (self-healing).
//!
//! ## How it works
//!
//! The Double Ratchet combines two ratchet mechanisms:
//!
//! 1. **DH Ratchet**: When a new message arrives with a new DH public key,
//!    a Diffie-Hellman exchange produces new root key material. This provides
//!    "future secrecy" — even if a chain key is compromised, the next DH
//!    ratchet step re-establishes security.
//!
//! 2. **Symmetric Ratchet (KDF chain)**: Each sent/received message advances
//!    a chain key forward using HMAC-SHA256. Old chain keys are deleted, so
//!    compromising the current state doesn't reveal past message keys.
//!
//! ## Encryption
//!
//! Each message is encrypted with AES-256-GCM using a unique message key
//! derived from the chain. The nonce is randomly generated per message.
//!
//! ## Out-of-order message handling
//!
//! If messages arrive out of order, we can "fast-forward" the receiving chain
//! to skip ahead, storing the skipped message keys for later decryption.
//! Skipped keys are bounded (MAX_SKIP) to prevent DoS via huge skip requests.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use rand_core::{OsRng, RngCore};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Maximum number of message keys we're willing to skip and store.
/// This bounds memory usage and prevents DoS from a peer claiming
/// an absurdly high message number.
const MAX_SKIP: u32 = 1000;

/// KDF info string for the root chain ratchet step.
const RATCHET_KDF_INFO: &[u8] = b"SofaMsg_DoubleRatchet_RootChain_v1";

/// KDF info string for deriving message keys from chain keys.
#[allow(dead_code)]
const MESSAGE_KEY_INFO: &[u8] = b"SofaMsg_DoubleRatchet_MessageKey_v1";

// ---------------------------------------------------------------------------
// Wire types — these go over the network
// ---------------------------------------------------------------------------

/// Header sent alongside each encrypted message. Contains the information
/// the recipient needs to perform DH ratchet steps and locate the correct
/// chain key for decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    /// The sender's current DH ratchet public key (X25519).
    /// When this changes, the recipient performs a DH ratchet step.
    #[serde(with = "x25519_pubkey_serde")]
    pub dh_public_key: X25519PublicKey,
    /// Number of messages sent in the *previous* sending chain
    /// (before the last DH ratchet). Lets the recipient know how many
    /// skipped message keys to store from the old chain.
    pub previous_chain_length: u32,
    /// Message number within the current sending chain (0-indexed).
    pub message_number: u32,
}

/// A fully encrypted message ready for transmission.
/// The header is sent in the clear (it contains no secret data —
/// just public keys and counters). The ciphertext is AES-256-GCM encrypted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    /// AES-256-GCM ciphertext (includes the 16-byte auth tag appended by aes-gcm).
    pub ciphertext: Vec<u8>,
    /// 96-bit random nonce used for this message's AES-256-GCM encryption.
    pub nonce: [u8; 12],
}

// ---------------------------------------------------------------------------
// Serde helper for X25519PublicKey (not Serialize by default)
// ---------------------------------------------------------------------------

mod x25519_pubkey_serde {
    use super::*;
    use serde::{Serializer, Deserializer, de};

    pub fn serialize<S: Serializer>(key: &X25519PublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<X25519PublicKey, D::Error> {
        let bytes: Vec<u8> = de::Deserialize::deserialize(d)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            de::Error::custom("X25519 public key must be exactly 32 bytes")
        })?;
        Ok(X25519PublicKey::from(arr))
    }
}

// ---------------------------------------------------------------------------
// Ratchet state
// ---------------------------------------------------------------------------

/// The full state of a Double Ratchet session.
///
/// Both the sender and receiver maintain one of these. It tracks:
/// - The current DH ratchet keypair
/// - The root key (ratcheted forward with each DH step)
/// - Sending and receiving chain keys (ratcheted forward with each message)
/// - Message counters
/// - Skipped message keys (for out-of-order delivery)
pub struct RatchetState {
    /// Our current DH ratchet keypair (X25519). Rotated on each DH ratchet step.
    dh_keypair_secret: X25519StaticSecret,
    dh_keypair_public: X25519PublicKey,

    /// The remote peer's current DH ratchet public key.
    /// `None` only for the initial sender before any reply is received.
    remote_dh_public: Option<X25519PublicKey>,

    /// Root key — ratcheted forward with each DH step. 32 bytes.
    root_key: [u8; 32],

    /// Sending chain key — ratcheted forward with each sent message.
    /// `None` if we haven't started a sending chain yet.
    sending_chain_key: Option<[u8; 32]>,

    /// Receiving chain key — ratcheted forward with each received message.
    /// `None` if we haven't started a receiving chain yet.
    receiving_chain_key: Option<[u8; 32]>,

    /// Number of messages sent in the current sending chain.
    send_message_number: u32,

    /// Number of messages received in the current receiving chain.
    recv_message_number: u32,

    /// Number of messages sent in the previous sending chain
    /// (before the last DH ratchet step we performed).
    previous_sending_chain_length: u32,

    /// Skipped message keys, indexed by (DH public key bytes, message number).
    /// These accumulate when messages arrive out of order.
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl RatchetState {
    /// Initialize the **sender** (Alice) side of a Double Ratchet session.
    ///
    /// Called after X3DH completes. Alice knows:
    /// - The shared secret (becomes the initial root key)
    /// - Bob's signed pre-key public (becomes the initial remote DH key)
    ///
    /// Alice immediately performs a DH ratchet step to derive her first
    /// sending chain key, since she's the one sending the first message.
    pub fn init_sender(
        shared_secret: [u8; 32],
        remote_dh_public: X25519PublicKey,
    ) -> Self {
        // Generate our first DH ratchet keypair.
        let dh_secret = X25519StaticSecret::random_from_rng(OsRng);
        let dh_public = X25519PublicKey::from(&dh_secret);

        // Perform the initial DH ratchet step to derive the first sending chain key.
        let dh_output = dh_secret.diffie_hellman(&remote_dh_public);
        let (new_root_key, sending_chain_key) = kdf_rk(&shared_secret, dh_output.as_bytes());

        RatchetState {
            dh_keypair_secret: dh_secret,
            dh_keypair_public: dh_public,
            remote_dh_public: Some(remote_dh_public),
            root_key: new_root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            send_message_number: 0,
            recv_message_number: 0,
            previous_sending_chain_length: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize the **receiver** (Bob) side of a Double Ratchet session.
    ///
    /// Bob uses his signed pre-key as the initial DH keypair (since that's
    /// what Alice used for her first DH ratchet step). He doesn't have a
    /// sending chain yet — that gets created when he sends his first reply.
    pub fn init_receiver(
        shared_secret: [u8; 32],
        our_spk_secret: X25519StaticSecret,
        our_spk_public: X25519PublicKey,
    ) -> Self {
        RatchetState {
            dh_keypair_secret: our_spk_secret,
            dh_keypair_public: our_spk_public,
            remote_dh_public: None,
            root_key: shared_secret,
            sending_chain_key: None,
            receiving_chain_key: None,
            send_message_number: 0,
            recv_message_number: 0,
            previous_sending_chain_length: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a plaintext message, advancing the sending chain.
    ///
    /// Returns an [`EncryptedMessage`] containing the header (public key +
    /// counters) and AES-256-GCM ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if the sending chain hasn't been initialized (shouldn't happen
    /// in correct usage — the sender always has a sending chain after init).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> EncryptedMessage {
        let chain_key = self
            .sending_chain_key
            .expect("sending chain must be initialized before encrypting");

        // Derive the message key and advance the chain key.
        let (new_chain_key, message_key) = kdf_ck(&chain_key);
        self.sending_chain_key = Some(new_chain_key);

        let header = MessageHeader {
            dh_public_key: self.dh_keypair_public,
            previous_chain_length: self.previous_sending_chain_length,
            message_number: self.send_message_number,
        };

        self.send_message_number += 1;

        // Encrypt with AES-256-GCM.
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .expect("message key is always 32 bytes");
        let nonce = Nonce::from_slice(&nonce_bytes);

        // We include the header as associated data (AD) so that tampering
        // with the header (e.g., changing message numbers) is also detected.
        let header_bytes = serde_json::to_vec(&header)
            .expect("header serialization should not fail");
        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &header_bytes,
            })
            .expect("AES-256-GCM encryption should not fail");

        EncryptedMessage {
            header,
            ciphertext,
            nonce: nonce_bytes,
        }
    }

    /// Decrypt a received [`EncryptedMessage`], handling DH ratchet steps
    /// and out-of-order delivery.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - The message number implies skipping more than [`MAX_SKIP`] messages
    /// - AES-256-GCM authentication fails (message was tampered with)
    pub fn decrypt(&mut self, msg: &EncryptedMessage) -> Result<Vec<u8>, &'static str> {
        // Step 1: Check if we already have a skipped key for this message.
        let dh_bytes = *msg.header.dh_public_key.as_bytes();
        if let Some(mk) = self.skipped_keys.remove(&(dh_bytes, msg.header.message_number)) {
            return decrypt_with_key(&mk, msg);
        }

        // Step 2: If the sender's DH key has changed, perform a DH ratchet step.
        let need_dh_ratchet = match &self.remote_dh_public {
            None => true,  // First message from this peer.
            Some(current) => current.as_bytes() != msg.header.dh_public_key.as_bytes(),
        };

        if need_dh_ratchet {
            // Skip any remaining messages from the old receiving chain.
            if self.receiving_chain_key.is_some() {
                self.skip_message_keys(msg.header.previous_chain_length)?;
            }

            // DH ratchet step: derive new receiving chain.
            self.previous_sending_chain_length = self.send_message_number;
            self.send_message_number = 0;
            self.recv_message_number = 0;
            self.remote_dh_public = Some(msg.header.dh_public_key);

            let dh_recv = self
                .dh_keypair_secret
                .diffie_hellman(&msg.header.dh_public_key);
            let (new_rk, recv_ck) = kdf_rk(&self.root_key, dh_recv.as_bytes());
            self.root_key = new_rk;
            self.receiving_chain_key = Some(recv_ck);

            // Generate a new DH keypair for our next sending chain.
            let new_dh_secret = X25519StaticSecret::random_from_rng(OsRng);
            let new_dh_public = X25519PublicKey::from(&new_dh_secret);

            let dh_send = new_dh_secret.diffie_hellman(&msg.header.dh_public_key);
            let (new_rk2, send_ck) = kdf_rk(&self.root_key, dh_send.as_bytes());
            self.root_key = new_rk2;
            self.sending_chain_key = Some(send_ck);
            self.dh_keypair_secret = new_dh_secret;
            self.dh_keypair_public = new_dh_public;
        }

        // Step 3: Skip message keys up to the received message number.
        self.skip_message_keys(msg.header.message_number)?;

        // Step 4: Derive the message key for this message.
        let recv_ck = self
            .receiving_chain_key
            .expect("receiving chain should be initialized by DH ratchet");
        let (new_ck, mk) = kdf_ck(&recv_ck);
        self.receiving_chain_key = Some(new_ck);
        self.recv_message_number += 1;

        decrypt_with_key(&mk, msg)
    }

    /// Skip message keys from `self.recv_message_number` up to (but not including)
    /// `until`, storing the derived keys for future out-of-order decryption.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), &'static str> {
        if until < self.recv_message_number {
            return Ok(());
        }

        let skip_count = until - self.recv_message_number;
        if skip_count > MAX_SKIP {
            return Err("Too many skipped messages — possible DoS attempt");
        }

        if let Some(mut ck) = self.receiving_chain_key {
            let dh_bytes = self
                .remote_dh_public
                .map(|k| *k.as_bytes())
                .unwrap_or([0u8; 32]);

            while self.recv_message_number < until {
                let (new_ck, mk) = kdf_ck(&ck);
                self.skipped_keys
                    .insert((dh_bytes, self.recv_message_number), mk);
                ck = new_ck;
                self.recv_message_number += 1;
            }
            self.receiving_chain_key = Some(ck);
        }
        Ok(())
    }

    /// Get the current DH ratchet public key (useful for debugging/inspection).
    pub fn dh_public_key(&self) -> &X25519PublicKey {
        &self.dh_keypair_public
    }
}

// ---------------------------------------------------------------------------
// KDF functions
// ---------------------------------------------------------------------------

/// Root key ratchet: KDF(root_key, dh_output) → (new_root_key, chain_key)
///
/// Uses HKDF-SHA256 with the current root key as salt and the DH output
/// as input keying material. Produces 64 bytes: first 32 = new root key,
/// last 32 = new chain key.
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 64];
    hk.expand(RATCHET_KDF_INFO, &mut output)
        .expect("64 bytes is within HKDF-SHA256's output limit");
    let mut new_rk = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_rk.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..64]);
    (new_rk, chain_key)
}

/// Chain key ratchet: KDF(chain_key) → (new_chain_key, message_key)
///
/// Uses HMAC-SHA256 with two different constants to derive:
/// - new_chain_key = HMAC(chain_key, 0x02)  — for the next message
/// - message_key   = HMAC(chain_key, 0x01)  — for this message's AES-GCM
///
/// This is the standard Signal approach: simple, efficient, and the
/// HMAC ensures the chain is one-way (can't reverse to find old keys).
fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Message key: HMAC(CK, 0x01)
    let mut mac_mk: Hmac<Sha256> =
        <Hmac<Sha256> as KeyInit>::new_from_slice(chain_key).expect("HMAC accepts any key size");
    mac_mk.update(&[0x01]);
    let mk_result = mac_mk.finalize().into_bytes();
    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&mk_result);

    // New chain key: HMAC(CK, 0x02)
    let mut mac_ck: Hmac<Sha256> =
        <Hmac<Sha256> as KeyInit>::new_from_slice(chain_key).expect("HMAC accepts any key size");
    mac_ck.update(&[0x02]);
    let ck_result = mac_ck.finalize().into_bytes();
    let mut new_chain_key = [0u8; 32];
    new_chain_key.copy_from_slice(&ck_result);

    (new_chain_key, message_key)
}

/// Decrypt a message using a specific message key.
fn decrypt_with_key(message_key: &[u8; 32], msg: &EncryptedMessage) -> Result<Vec<u8>, &'static str> {
    let cipher =
        Aes256Gcm::new_from_slice(message_key).expect("message key is always 32 bytes");
    let nonce = Nonce::from_slice(&msg.nonce);

    let header_bytes = serde_json::to_vec(&msg.header)
        .expect("header serialization should not fail");

    cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: &msg.ciphertext,
            aad: &header_bytes,
        })
        .map_err(|_| "AES-256-GCM authentication failed — message may have been tampered with")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: set up a sender/receiver pair from a shared secret.
    fn make_ratchet_pair() -> (RatchetState, RatchetState) {
        // Simulate X3DH having produced a shared secret.
        let shared_secret = {
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s
        };

        // Bob's "signed pre-key" — in real usage this comes from X3DH.
        let bob_spk_secret = X25519StaticSecret::random_from_rng(OsRng);
        let bob_spk_public = X25519PublicKey::from(&bob_spk_secret);

        let alice = RatchetState::init_sender(shared_secret, bob_spk_public);
        let bob = RatchetState::init_receiver(shared_secret, bob_spk_secret, bob_spk_public);

        (alice, bob)
    }

    #[test]
    fn encrypt_then_decrypt_recovers_plaintext() {
        let (mut alice, mut bob) = make_ratchet_pair();

        let plaintext = b"Hello Bob, this is a secret message!";
        let encrypted = alice.encrypt(plaintext);
        let decrypted = bob.decrypt(&encrypted).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn multiple_messages_in_sequence() {
        let (mut alice, mut bob) = make_ratchet_pair();

        for i in 0..10 {
            let msg = format!("Message number {}", i);
            let encrypted = alice.encrypt(msg.as_bytes());
            let decrypted = bob.decrypt(&encrypted).expect("decryption should succeed");
            assert_eq!(decrypted, msg.as_bytes());
        }
    }

    #[test]
    fn bidirectional_conversation() {
        let (mut alice, mut bob) = make_ratchet_pair();

        // Alice sends to Bob.
        let e1 = alice.encrypt(b"Hey Bob");
        let d1 = bob.decrypt(&e1).unwrap();
        assert_eq!(d1, b"Hey Bob");

        // Bob replies to Alice (triggers DH ratchet on Alice's side).
        let e2 = bob.encrypt(b"Hey Alice");
        let d2 = alice.decrypt(&e2).unwrap();
        assert_eq!(d2, b"Hey Alice");

        // Alice replies again.
        let e3 = alice.encrypt(b"How are you?");
        let d3 = bob.decrypt(&e3).unwrap();
        assert_eq!(d3, b"How are you?");

        // Bob replies again.
        let e4 = bob.encrypt(b"Good, you?");
        let d4 = alice.decrypt(&e4).unwrap();
        assert_eq!(d4, b"Good, you?");
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = make_ratchet_pair();

        // Alice sends 3 messages.
        let e0 = alice.encrypt(b"msg 0");
        let e1 = alice.encrypt(b"msg 1");
        let e2 = alice.encrypt(b"msg 2");

        // Bob receives them out of order: 2, 0, 1.
        let d2 = bob.decrypt(&e2).unwrap();
        assert_eq!(d2, b"msg 2");

        let d0 = bob.decrypt(&e0).unwrap();
        assert_eq!(d0, b"msg 0");

        let d1 = bob.decrypt(&e1).unwrap();
        assert_eq!(d1, b"msg 1");
    }

    #[test]
    fn dh_ratchet_produces_new_keys_forward_secrecy() {
        let (mut alice, mut bob) = make_ratchet_pair();

        // Record Alice's initial DH public key.
        let alice_dh_1 = *alice.dh_public_key().as_bytes();

        // Alice sends, Bob receives.
        let e1 = alice.encrypt(b"first");
        bob.decrypt(&e1).unwrap();

        // Bob replies — this triggers a DH ratchet on both sides.
        let e2 = bob.encrypt(b"reply");
        alice.decrypt(&e2).unwrap();

        // Alice's DH key should have changed after receiving Bob's reply.
        let alice_dh_2 = *alice.dh_public_key().as_bytes();
        assert_ne!(
            alice_dh_1, alice_dh_2,
            "DH ratchet must produce a new DH keypair (forward secrecy)"
        );

        // Alice sends again with the new DH key.
        let e3 = alice.encrypt(b"second");
        let d3 = bob.decrypt(&e3).unwrap();
        assert_eq!(d3, b"second");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = make_ratchet_pair();

        let mut encrypted = alice.encrypt(b"tamper test");
        // Flip a bit in the ciphertext.
        if let Some(byte) = encrypted.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = bob.decrypt(&encrypted);
        assert!(
            result.is_err(),
            "Tampered ciphertext must be rejected by GCM auth"
        );
    }

    #[test]
    fn tampered_header_is_rejected() {
        let (mut alice, mut bob) = make_ratchet_pair();

        let mut encrypted = alice.encrypt(b"header tamper test");
        // Change the message number in the header.
        encrypted.header.message_number = 999;

        let result = bob.decrypt(&encrypted);
        assert!(
            result.is_err(),
            "Tampered header must be rejected because header is in GCM AAD"
        );
    }

    #[test]
    fn each_message_uses_different_key() {
        let (mut alice, _bob) = make_ratchet_pair();

        let e1 = alice.encrypt(b"same plaintext");
        let e2 = alice.encrypt(b"same plaintext");

        // Even with identical plaintext, ciphertexts must differ
        // (different message keys + different nonces).
        assert_ne!(
            e1.ciphertext, e2.ciphertext,
            "Each message must use a unique key+nonce"
        );
        assert_ne!(
            e1.nonce, e2.nonce,
            "Each message must use a unique nonce"
        );
    }

    #[test]
    fn max_skip_exceeded_returns_error() {
        let (mut alice, mut bob) = make_ratchet_pair();

        // Send MAX_SKIP + 2 messages to guarantee exceeding the limit.
        let mut messages = Vec::new();
        for i in 0..(MAX_SKIP + 2) {
            let msg = format!("msg {}", i);
            messages.push(alice.encrypt(msg.as_bytes()));
        }

        // Try to decrypt only the last message — this requires skipping
        // MAX_SKIP + 1 messages, which exceeds the limit.
        let result = bob.decrypt(messages.last().unwrap());
        assert!(
            result.is_err(),
            "Should reject skip count exceeding MAX_SKIP"
        );
    }
}

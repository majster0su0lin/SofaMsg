//! # X3DH — Extended Triple Diffie-Hellman Key Agreement
//!
//! Implements the [Signal X3DH specification](https://signal.org/docs/specifications/x3dh/)
//! adapted for SofaMsg's Ed25519-based identity keys.
//!
//! ## Protocol overview
//!
//! X3DH establishes a shared secret between two parties (Alice and Bob) who
//! may not be online simultaneously. Bob publishes a **pre-key bundle** to
//! the DHT; Alice fetches it and computes a shared secret using four (or three,
//! if no one-time pre-key is available) Diffie-Hellman operations:
//!
//! ```text
//! DH1 = DH(IK_A, SPK_B)     — Alice's identity ↔ Bob's signed pre-key
//! DH2 = DH(EK_A, IK_B)      — Alice's ephemeral ↔ Bob's identity
//! DH3 = DH(EK_A, SPK_B)     — Alice's ephemeral ↔ Bob's signed pre-key
//! DH4 = DH(EK_A, OPK_B)     — Alice's ephemeral ↔ Bob's one-time pre-key (optional)
//! ```
//!
//! The shared secret `SK = KDF(DH1 || DH2 || DH3 [|| DH4])` becomes the
//! initial root key for the Double Ratchet.
//!
//! ## Ed25519 → X25519 conversion
//!
//! SofaMsg uses Ed25519 for identity (signing) but X3DH requires X25519 (DH).
//! We convert Ed25519 keys to their X25519 (Montgomery) form using the
//! birational map between the two curves — this is a standard, well-understood
//! conversion (used by Signal, libsodium, etc.).

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use sha2::Sha256;
use hkdf::Hkdf;
use rand_core::OsRng;

/// The "info" string for HKDF when deriving the shared secret from DH outputs.
/// Using a unique, application-specific info string prevents cross-protocol attacks.
const X3DH_KDF_INFO: &[u8] = b"SofaMsg_X3DH_SharedSecret_v1";

/// 32 bytes of 0xFF, prepended to KDF input per Signal's X3DH spec to ensure
/// the DH output is never all-zeros (which would be a cryptographic failure case).
const X3DH_KDF_SALT: [u8; 32] = [0xFF; 32];

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// A medium-term X25519 keypair signed by the identity key.
/// Rotated periodically (e.g., weekly). The signature lets the initiator
/// verify that this pre-key genuinely belongs to the claimed identity.
#[derive(Clone)]
pub struct SignedPreKey {
    pub secret: X25519StaticSecret,
    pub public: X25519PublicKey,
    /// Ed25519 signature over the X25519 public key bytes, made by the identity key.
    pub signature: Signature,
}

/// A single-use X25519 keypair. Consumed by exactly one X3DH handshake,
/// then discarded. Provides an extra layer of forward secrecy: even if
/// the signed pre-key is later compromised, past sessions that used a
/// one-time pre-key remain safe.
#[derive(Clone)]
pub struct OneTimePreKey {
    pub secret: X25519StaticSecret,
    pub public: X25519PublicKey,
}

/// The public portion of a user's pre-key bundle, published to the DHT
/// so that others can initiate sessions without the user being online.
#[derive(Clone)]
pub struct PreKeyBundle {
    /// The user's long-term Ed25519 identity public key.
    pub identity_key: VerifyingKey,
    /// Signed pre-key (X25519 public half + Ed25519 signature).
    pub signed_prekey_public: X25519PublicKey,
    pub signed_prekey_signature: Signature,
    /// Optional one-time pre-key. If `None`, X3DH falls back to 3-DH
    /// (slightly weaker forward secrecy but still secure).
    pub one_time_prekey_public: Option<X25519PublicKey>,
}

/// Output from the initiator (Alice) side of X3DH.
pub struct X3dhInitiatorOutput {
    /// The derived shared secret (32 bytes), used as the initial root key
    /// for the Double Ratchet.
    pub shared_secret: [u8; 32],
    /// Alice's ephemeral public key — must be sent to Bob so he can
    /// compute the same shared secret.
    pub ephemeral_public_key: X25519PublicKey,
}

/// Output from the responder (Bob) side of X3DH.
pub struct X3dhResponderOutput {
    /// The derived shared secret — must match Alice's.
    pub shared_secret: [u8; 32],
}

// ---------------------------------------------------------------------------
// Ed25519 ↔ X25519 conversion
// ---------------------------------------------------------------------------

/// Convert an Ed25519 **signing** (private) key to an X25519 static secret.
///
/// The Ed25519 private key is a 32-byte seed; we use SHA-512 to expand it
/// (matching ed25519-dalek's internal derivation), then clamp the lower 32
/// bytes per the X25519 spec to produce the scalar.
///
/// # Why this works
///
/// Ed25519 and X25519 operate on the same underlying curve (Curve25519),
/// just using different coordinate representations (Edwards vs Montgomery).
/// The private scalar is the same in both cases — we just need to extract
/// it from Ed25519's expanded key format.
pub fn ed25519_signing_key_to_x25519(signing_key: &SigningKey) -> X25519StaticSecret {
    use sha2::{Sha512, Digest};
    let expanded = Sha512::digest(signing_key.as_bytes());
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&expanded[..32]);
    // Clamp per X25519/RFC 7748 — clear the low 3 bits, clear bit 255, set bit 254.
    // x25519-dalek does its own clamping internally, but we do it here for clarity.
    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;
    X25519StaticSecret::from(x25519_bytes)
}

/// Convert an Ed25519 **verifying** (public) key to an X25519 public key.
///
/// This uses the standard Edwards→Montgomery birational map:
///   u = (1 + y) / (1 - y)  (mod p)
///
/// We rely on `curve25519-dalek`'s `MontgomeryPoint` conversion which
/// implements this map correctly.
pub fn ed25519_verifying_key_to_x25519(verifying_key: &VerifyingKey) -> X25519PublicKey {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY::from_slice(verifying_key.as_bytes())
        .expect("VerifyingKey is always 32 bytes");
    let edwards_point = compressed
        .decompress()
        .expect("a valid VerifyingKey always decompresses");
    let montgomery = edwards_point.to_montgomery();
    X25519PublicKey::from(montgomery.to_bytes())
}

// ---------------------------------------------------------------------------
// Pre-key generation
// ---------------------------------------------------------------------------

/// Generate a new signed pre-key, signed by the given identity signing key.
///
/// The signature covers the raw X25519 public key bytes, binding the pre-key
/// to the identity. Anyone with the identity's public key can verify this
/// binding, preventing a MitM from substituting their own pre-key.
pub fn generate_signed_prekey(identity_signing_key: &SigningKey) -> SignedPreKey {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    let signature = identity_signing_key.sign(public.as_bytes());
    SignedPreKey { secret, public, signature }
}

/// Generate a new one-time pre-key (no signature needed — they're bound
/// to the bundle by the signed pre-key's presence).
pub fn generate_one_time_prekey() -> OneTimePreKey {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    OneTimePreKey { secret, public }
}

// ---------------------------------------------------------------------------
// X3DH protocol execution
// ---------------------------------------------------------------------------

/// Derive the shared secret from concatenated DH outputs using HKDF-SHA256.
///
/// Per Signal's X3DH spec, the input keying material is:
///   IKM = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4]
///
/// The leading 0xFF block ensures non-zero IKM even in degenerate cases.
fn kdf(dh_outputs: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&X3DH_KDF_SALT), dh_outputs);
    let mut shared_secret = [0u8; 32];
    hk.expand(X3DH_KDF_INFO, &mut shared_secret)
        .expect("32 bytes is within HKDF-SHA256's output limit");
    shared_secret
}

/// **Initiator (Alice)** side of X3DH.
///
/// Alice fetches Bob's [`PreKeyBundle`] from the DHT and computes the shared
/// secret. She must then send her ephemeral public key (and her identity key
/// if Bob doesn't already have it) to Bob alongside the first Double Ratchet
/// message.
///
/// # Errors
///
/// Returns `Err` if the signed pre-key's signature doesn't verify against
/// Bob's claimed identity key — this prevents MitM pre-key substitution.
pub fn initiate_x3dh(
    our_identity_signing_key: &SigningKey,
    their_bundle: &PreKeyBundle,
) -> Result<X3dhInitiatorOutput, &'static str> {
    // Step 1: Verify that Bob's signed pre-key is actually signed by Bob's identity key.
    their_bundle
        .identity_key
        .verify(
            their_bundle.signed_prekey_public.as_bytes(),
            &their_bundle.signed_prekey_signature,
        )
        .map_err(|_| "Signed pre-key signature verification failed")?;

    // Step 2: Convert our Ed25519 identity key to X25519 for DH.
    let our_x25519_secret = ed25519_signing_key_to_x25519(our_identity_signing_key);

    // Step 3: Generate a fresh ephemeral X25519 keypair for this session.
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Step 4: Compute the DH operations.
    // DH1: our identity ↔ their signed pre-key
    let dh1 = our_x25519_secret.diffie_hellman(&their_bundle.signed_prekey_public);
    // DH2: our ephemeral ↔ their identity (converted to X25519)
    let their_x25519_identity = ed25519_verifying_key_to_x25519(&their_bundle.identity_key);
    let dh2 = ephemeral_secret.diffie_hellman(&their_x25519_identity);
    // DH3: our ephemeral ↔ their signed pre-key
    let dh3 = ephemeral_secret.diffie_hellman(&their_bundle.signed_prekey_public);

    // Step 5: Concatenate DH outputs; optionally include DH4 if OPK is present.
    let mut dh_concat = Vec::with_capacity(32 * 4);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = &their_bundle.one_time_prekey_public {
        // DH4: our ephemeral ↔ their one-time pre-key
        let dh4 = ephemeral_secret.diffie_hellman(opk);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    let shared_secret = kdf(&dh_concat);

    Ok(X3dhInitiatorOutput {
        shared_secret,
        ephemeral_public_key: ephemeral_public,
    })
}

/// **Responder (Bob)** side of X3DH.
///
/// Bob receives Alice's initial message containing her identity key and
/// ephemeral public key. He uses his own pre-key material to derive the
/// same shared secret.
///
/// # Arguments
///
/// - `our_identity_signing_key` — Bob's long-term Ed25519 signing key
/// - `our_signed_prekey` — Bob's signed pre-key (the one Alice used)
/// - `our_one_time_prekey` — The specific OPK Alice used, if any.
///   **Must be discarded after this call** — one-time means one-time.
/// - `their_identity_key` — Alice's Ed25519 verifying (public) key
/// - `their_ephemeral_key` — Alice's ephemeral X25519 public key
///   (received in the initial message)
pub fn respond_x3dh(
    our_identity_signing_key: &SigningKey,
    our_signed_prekey: &SignedPreKey,
    our_one_time_prekey: Option<&OneTimePreKey>,
    their_identity_key: &VerifyingKey,
    their_ephemeral_key: &X25519PublicKey,
) -> X3dhResponderOutput {
    // Convert keys to X25519 form.
    let our_x25519_secret = ed25519_signing_key_to_x25519(our_identity_signing_key);
    let their_x25519_identity = ed25519_verifying_key_to_x25519(their_identity_key);

    // Mirror Alice's DH operations (note: DH is commutative — DH(a, B) == DH(b, A)).
    // DH1: their identity ↔ our signed pre-key
    //   Alice computed: DH(IK_A_secret, SPK_B_public)
    //   Bob computes:   DH(SPK_B_secret, IK_A_public)  ← same shared secret
    let dh1 = our_signed_prekey.secret.diffie_hellman(&their_x25519_identity);

    // DH2: their ephemeral ↔ our identity
    let dh2 = our_x25519_secret.diffie_hellman(their_ephemeral_key);

    // DH3: their ephemeral ↔ our signed pre-key
    let dh3 = our_signed_prekey.secret.diffie_hellman(their_ephemeral_key);

    let mut dh_concat = Vec::with_capacity(32 * 4);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = our_one_time_prekey {
        // DH4: their ephemeral ↔ our one-time pre-key
        let dh4 = opk.secret.diffie_hellman(their_ephemeral_key);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    let shared_secret = kdf(&dh_concat);

    X3dhResponderOutput { shared_secret }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    /// Helper: create a full identity + pre-key bundle for testing.
    fn make_test_bundle(
        with_opk: bool,
    ) -> (SigningKey, SignedPreKey, Option<OneTimePreKey>, PreKeyBundle) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let spk = generate_signed_prekey(&signing_key);
        let opk = if with_opk {
            Some(generate_one_time_prekey())
        } else {
            None
        };

        let bundle = PreKeyBundle {
            identity_key: signing_key.verifying_key(),
            signed_prekey_public: spk.public,
            signed_prekey_signature: spk.signature,
            one_time_prekey_public: opk.as_ref().map(|o| o.public),
        };

        (signing_key, spk, opk, bundle)
    }

    #[test]
    fn x3dh_both_sides_derive_same_secret_with_opk() {
        // Alice and Bob must derive the same shared secret.
        let alice_signing = SigningKey::generate(&mut OsRng);
        let (bob_signing, bob_spk, bob_opk, bob_bundle) = make_test_bundle(true);

        let alice_output = initiate_x3dh(&alice_signing, &bob_bundle)
            .expect("X3DH initiation should succeed");

        let bob_output = respond_x3dh(
            &bob_signing,
            &bob_spk,
            bob_opk.as_ref(),
            &alice_signing.verifying_key(),
            &alice_output.ephemeral_public_key,
        );

        assert_eq!(
            alice_output.shared_secret, bob_output.shared_secret,
            "Both sides must derive the same shared secret"
        );
    }

    #[test]
    fn x3dh_both_sides_derive_same_secret_without_opk() {
        // X3DH must also work without a one-time pre-key (3-DH fallback).
        let alice_signing = SigningKey::generate(&mut OsRng);
        let (bob_signing, bob_spk, _, bob_bundle) = make_test_bundle(false);

        let alice_output = initiate_x3dh(&alice_signing, &bob_bundle)
            .expect("X3DH initiation should succeed");

        let bob_output = respond_x3dh(
            &bob_signing,
            &bob_spk,
            None,
            &alice_signing.verifying_key(),
            &alice_output.ephemeral_public_key,
        );

        assert_eq!(
            alice_output.shared_secret, bob_output.shared_secret,
            "3-DH fallback must also produce matching secrets"
        );
    }

    #[test]
    fn x3dh_different_sessions_produce_different_secrets() {
        // Two independent X3DH handshakes should never produce the same secret
        // (different ephemeral keys ensure this).
        let alice_signing = SigningKey::generate(&mut OsRng);
        let (_, _, _, bob_bundle) = make_test_bundle(false);

        let out1 = initiate_x3dh(&alice_signing, &bob_bundle).unwrap();
        let out2 = initiate_x3dh(&alice_signing, &bob_bundle).unwrap();

        assert_ne!(
            out1.shared_secret, out2.shared_secret,
            "Different sessions must produce different secrets"
        );
        assert_ne!(
            out1.ephemeral_public_key.as_bytes(),
            out2.ephemeral_public_key.as_bytes(),
            "Each session must use a fresh ephemeral key"
        );
    }

    #[test]
    fn x3dh_rejects_invalid_spk_signature() {
        // If someone tampers with the signed pre-key's signature, X3DH must fail.
        let alice_signing = SigningKey::generate(&mut OsRng);
        let (_, _, _, mut bob_bundle) = make_test_bundle(true);

        // Corrupt the signature by replacing it with a signature from a different key.
        let evil_key = SigningKey::generate(&mut OsRng);
        bob_bundle.signed_prekey_signature =
            evil_key.sign(bob_bundle.signed_prekey_public.as_bytes());

        let result = initiate_x3dh(&alice_signing, &bob_bundle);
        assert!(
            result.is_err(),
            "Must reject bundle with invalid SPK signature"
        );
    }

    #[test]
    fn ed25519_to_x25519_roundtrip_consistency() {
        // Verify that the Ed25519→X25519 conversion is deterministic:
        // converting the same key twice must produce the same X25519 key.
        let signing_key = SigningKey::generate(&mut OsRng);
        let x1 = ed25519_signing_key_to_x25519(&signing_key);
        let x2 = ed25519_signing_key_to_x25519(&signing_key);

        let pub1 = X25519PublicKey::from(&x1);
        let pub2 = X25519PublicKey::from(&x2);
        assert_eq!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn ed25519_to_x25519_dh_agreement() {
        // Two parties convert their Ed25519 keys to X25519 and perform DH —
        // both must get the same shared secret.
        let a_ed = SigningKey::generate(&mut OsRng);
        let b_ed = SigningKey::generate(&mut OsRng);

        let a_x = ed25519_signing_key_to_x25519(&a_ed);
        let b_x = ed25519_signing_key_to_x25519(&b_ed);

        let a_pub = ed25519_verifying_key_to_x25519(&a_ed.verifying_key());
        let b_pub = ed25519_verifying_key_to_x25519(&b_ed.verifying_key());

        let shared_ab = a_x.diffie_hellman(&b_pub);
        let shared_ba = b_x.diffie_hellman(&a_pub);

        assert_eq!(
            shared_ab.as_bytes(),
            shared_ba.as_bytes(),
            "DH must be commutative after Ed25519→X25519 conversion"
        );
    }
}

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Keypair {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_keypair() {
        let kp = Keypair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn two_generated_keys_are_different() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }
}

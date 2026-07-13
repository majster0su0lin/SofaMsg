use crate::keys::Keypair;
use sha2::{Digest, Sha256};

const ACCOUNT_ID_PREFIX: &str = "sb_";

pub fn derive_account_id(keypair: &Keypair) -> String {
    let pubkey_bytes = keypair.public_key_bytes();
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let hash = hasher.finalize();
    let encoded = bs58::encode(hash).into_string();
    format!("{ACCOUNT_ID_PREFIX}{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    #[test]
    fn account_id_has_expected_prefix() {
        let kp = Keypair::generate();
        let id = derive_account_id(&kp);
        assert!(id.starts_with("sb_"));
    }

    #[test]
    fn same_keypair_always_derives_same_id() {
        let kp = Keypair::generate();
        let id1 = derive_account_id(&kp);
        let id2 = derive_account_id(&kp);
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_keypairs_derive_different_ids() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        assert_ne!(derive_account_id(&kp1), derive_account_id(&kp2));
    }
}

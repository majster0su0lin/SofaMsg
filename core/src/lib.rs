mod keys;
mod identity;
mod vault;

pub use keys::Keypair;
pub use identity::derive_account_id;
pub use vault::{decrypt, derive_key, encrypt, VaultKey};

pub fn create_new_identity() -> (Keypair, String) {
    let keypair = Keypair::generate();
    let account_id = derive_account_id(&keypair);
    (keypair, account_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_identity_returns_matching_pair() {
        let (keypair, account_id) = create_new_identity();
        assert_eq!(derive_account_id(&keypair), account_id);
    }
}

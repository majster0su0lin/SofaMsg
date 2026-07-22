mod decoy;
pub mod e2e;
mod identity;
pub mod invite;
mod keys;
mod storage;
mod vault;

pub use decoy::{generate_decoy_content, DecoyConversation, DecoyMessage};
pub use e2e::{
    generate_one_time_prekey, generate_signed_prekey, initiate_x3dh, respond_x3dh,
    EncryptedMessage, MessageHeader, OneTimePreKey, PreKeyBundle, RatchetState, Session,
    SessionManager, SignedPreKey, X3dhInitiatorOutput, X3dhResponderOutput,
};
pub use identity::derive_account_id;
pub use invite::{InviteError, InvitePayload};
pub use keys::Keypair;
pub use storage::{
    chaff_count, clear_chaff, delete_message, ensure_schema, get_messages,
    get_recent_conversations, insert_message, open_encrypted_db, pad_chaff, StoredMessage,
};
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

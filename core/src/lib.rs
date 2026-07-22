mod keys;
mod identity;
mod vault;
mod storage;
mod decoy;
pub mod invite;
pub mod e2e;

pub use keys::Keypair;
pub use identity::derive_account_id;
pub use vault::{decrypt, derive_key, encrypt, VaultKey};
pub use e2e::{
    PreKeyBundle, X3dhInitiatorOutput, X3dhResponderOutput,
    SignedPreKey, OneTimePreKey,
    generate_signed_prekey, generate_one_time_prekey,
    initiate_x3dh, respond_x3dh,
    RatchetState, MessageHeader, EncryptedMessage,
    Session, SessionManager,
};
pub use storage::{
    ensure_schema, open_encrypted_db,
    StoredMessage, insert_message, get_messages, get_recent_conversations, delete_message,
    pad_chaff, chaff_count, clear_chaff,
};
pub use decoy::{generate_decoy_content, DecoyConversation, DecoyMessage};
pub use invite::{InvitePayload, InviteError};

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

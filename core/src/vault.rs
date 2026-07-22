use aes::Aes256;
use argon2::Argon2;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub struct VaultKey([u8; 32]);

impl VaultKey {
    pub fn as_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub fn derive_key(pin: &str, salt: &[u8; 16]) -> VaultKey {
    let argon2 = Argon2::default();
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut output)
        .expect("Argon2 key derivation failed");
    VaultKey(output)
}
pub fn encrypt(key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new(&key.0.into(), &iv.into());

    // encrypt_padded_mut needs a buffer big enough for the plaintext
    // PLUS up to one full block of PKCS7 padding, unlike the "_vec_mut"
    // convenience method which isn't available without the `alloc`
    // feature on the `cipher` crate. We size the buffer by hand here.
    let block_size = 16;
    let pad_len = block_size - (plaintext.len() % block_size);
    let mut buf = vec![0u8; plaintext.len() + pad_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let ciphertext_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .expect("buffer was sized correctly above")
        .len();
    buf.truncate(ciphertext_len);

    let mut output = Vec::with_capacity(16 + buf.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&buf);
    output
}

pub fn decrypt(key: &VaultKey, blob: &[u8]) -> Vec<u8> {
    if blob.len() < 16 {
        return Vec::new();
    }
    let (iv, ciphertext) = blob.split_at(16);
    let iv: [u8; 16] = iv.try_into().expect("split_at(16) guarantees length 16");

    let cipher = Aes256CbcDec::new(&key.0.into(), &iv.into());
    let mut buf = ciphertext.to_vec();

    match cipher.decrypt_padded_mut::<Pkcs7>(&mut buf) {
        Ok(plaintext) => plaintext.to_vec(),
        Err(_) => buf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_key_recovers_original_plaintext() {
        let salt = [7u8; 16];
        let key = derive_key("1234", &salt);
        let plaintext = b"hello sofa";
        let ciphertext = encrypt(&key, plaintext);
        let recovered = decrypt(&key, &ciphertext);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_does_not_panic_and_returns_something() {
        let real_salt = [7u8; 16];
        let duress_salt = [9u8; 16];
        let real_key = derive_key("1234", &real_salt);
        let wrong_key = derive_key("9999", &duress_salt);

        let ciphertext = encrypt(&real_key, b"real secret data");
        let result = decrypt(&wrong_key, &ciphertext);
        let _ = result;
    }

    #[test]
    fn same_pin_and_salt_always_derives_same_key() {
        let salt = [3u8; 16];
        let key1 = derive_key("4242", &salt);
        let key2 = derive_key("4242", &salt);
        assert_eq!(key1.0, key2.0);
    }

    #[test]
    fn different_salts_produce_different_keys_from_same_pin() {
        let key1 = derive_key("1234", &[1u8; 16]);
        let key2 = derive_key("1234", &[2u8; 16]);
        assert_ne!(key1.0, key2.0);
    }
}

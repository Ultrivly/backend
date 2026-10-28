









use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct Secrets {
    cipher: Aes256Gcm,
}

impl Secrets {
    
    pub fn from_base64_key(key: &str) -> anyhow::Result<Self> {
        let bytes = STANDARD
            .decode(key.trim())
            .context("ULTRIVLY_SECRET_KEY is not valid base64")?;
        if bytes.len() != 32 {
            bail!(
                "ULTRIVLY_SECRET_KEY must decode to 32 bytes, not {}",
                bytes.len()
            );
        }
        let cipher = Aes256Gcm::new_from_slice(&bytes).expect("length checked above");
        Ok(Self { cipher })
    }

    
    pub fn generate_key() -> String {
        STANDARD.encode(random_bytes::<32>())
    }

    pub fn encrypt(&self, context: &str, plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..]).expect("12-byte nonce");
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: context.as_bytes(),
                },
            )
            .expect("AES-GCM encryption does not fail for in-memory buffers");

        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    
    
    pub fn decrypt(&self, context: &str, stored: &[u8]) -> anyhow::Result<Vec<u8>> {
        if stored.len() < 1 + NONCE_LEN || stored[0] != VERSION {
            bail!("unrecognized encrypted secret format");
        }
        let nonce = Nonce::<Aes256Gcm>::try_from(&stored[1..1 + NONCE_LEN]).expect("12-byte nonce");
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &stored[1 + NONCE_LEN..],
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("could not decrypt secret ({context}); wrong ULTRIVLY_SECRET_KEY?")
            })
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    
    rand::fill(&mut bytes[..]);
    bytes
}


pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}



pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_the_wrong_context_or_key() {
        let secrets = Secrets::from_base64_key(&Secrets::generate_key()).unwrap();
        let stored = secrets.encrypt("mfa_factor:1", b"seed");
        assert_eq!(secrets.decrypt("mfa_factor:1", &stored).unwrap(), b"seed");
        assert!(secrets.decrypt("mfa_factor:2", &stored).is_err());

        let other = Secrets::from_base64_key(&Secrets::generate_key()).unwrap();
        assert!(other.decrypt("mfa_factor:1", &stored).is_err());

        let mut tampered = stored.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(secrets.decrypt("mfa_factor:1", &tampered).is_err());
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(Secrets::from_base64_key("not base64!").is_err());
        assert!(Secrets::from_base64_key(&STANDARD.encode([0u8; 16])).is_err());
    }
}

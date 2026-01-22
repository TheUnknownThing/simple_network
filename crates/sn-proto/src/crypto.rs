use aead::{Aead, KeyInit};
use base64::Engine;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::{Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use crate::wire::NodeId;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid PSK length: expected 32 bytes")]
    InvalidPskLength,

    #[error("crypto failure")]
    CryptoFailure,
}

pub fn decode_psk_base64(psk_base64: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(psk_base64)
        .map_err(|_| CryptoError::InvalidPskLength)?;

    if bytes.len() != 32 {
        return Err(CryptoError::InvalidPskLength);
    }

    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

pub fn derive_node_key(psk: &[u8; 32], node_id: NodeId) -> [u8; 32] {
    // HKDF(psk, info = "sn/node-key" || node_id)
    let hk = Hkdf::<Sha256>::new(None, psk);
    let mut okm = [0u8; 32];

    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"sn/node-key");
    info.extend_from_slice(node_id.as_bytes());

    hk.expand(&info, &mut okm)
        .expect("HKDF expand must not fail for 32-byte okm");

    okm
}

pub fn seal(
    node_key: &[u8; 32],
    nonce12: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(node_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce12);

    cipher
        .encrypt(
            nonce,
            aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)
}

pub fn open(
    node_key: &[u8; 32],
    nonce12: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(node_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce12);

    cipher
        .decrypt(
            nonce,
            aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)
}

pub fn random_nonce12() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).expect("getrandom failed");
    nonce
}

pub fn node_id_from_uuid(uuid: Uuid) -> NodeId {
    NodeId(uuid)
}

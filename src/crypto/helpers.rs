use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use sha2::Digest;
use crate::errors::{DonutError, DonutResult};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;

/// Sha256 helper
pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(bytes).to_vec()
}

/// MD5 helper
pub fn md5(bytes: &[u8]) -> Vec<u8> {
    md5::compute(bytes).to_vec()
}


/// XOR helper
pub fn xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let len = key.len();
    bytes.iter().enumerate().map(|(i, byte)| byte ^ key[i % len ]).collect()
}

/// AES-256-CBC encrypts a plaintext buffer with a given key and IV
pub fn aes256_cbc_encrypt(plaintext: &mut [u8], key: &[u8], iv: &[u8]) -> DonutResult<Vec<u8>> {
    if key.len() != 32 { return Err(DonutError::ParseFailed); }
    if iv.len() != 16 { return Err(DonutError::ParseFailed); }

    let ec = Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| DonutError::CryptoError )?;
    Ok(ec.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

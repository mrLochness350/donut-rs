use alloc::vec::Vec;
use azathoth_utils::codec::{Codec, Decoder, Encoder};
use azathoth_utils::errors::AzUtilResult;
use crate::crypto::aes::decrypt_cbc;
#[cfg(feature = "std")]
use crate::crypto::helpers::{aes256_cbc_encrypt, xor};
use crate::types::enums::DonutCryptoProvider;
use crate::utils::globals::{from_hex, pop_exact_vec};
use crate::errors::DonutResult;
use crate::prelude::DonutError;

///**This is still WIP and may change in the future**
/// Encrypts and Decrypts data
///
/// This struct is the way the loaders decrypt and encrypt the instances
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct DonutCrypto {
    /// Key value (32 bytes)
    pub key: Vec<u8>,
    /// IV Value (16 bytes)
    pub iv: Vec<u8>,
    /// Crypto provider
    pub provider: DonutCryptoProvider
}

impl Codec for DonutCrypto {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_slice(&self.key)?;
        enc.push_slice(&self.iv)?;
        self.provider.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        Ok(Self {
            key: dec.read_vec()?,
            iv: dec.read_vec()?,
            provider: DonutCryptoProvider::decode(dec)?,
        })
    }
}

impl DonutCrypto {
    /// Decrypts a given buffer
    pub fn decrypt(&self, data: &[u8]) -> DonutResult<Vec<u8>> {
        match self.provider {
            DonutCryptoProvider::Aes => {
                decrypt_cbc(data, &self.key, &self.iv)
            }
            DonutCryptoProvider::Xor => {
                let len = self.key.len();
                Ok(data.iter().enumerate().map(|(i, byte)| byte ^ self.key[i % len ]).collect())
            }
            DonutCryptoProvider::None => {
                Ok(data.to_vec())
            }
        }
    }

    /// Encrypts a given byte array
    ///
    /// This uses the [`DonutCrypto`] parameter to configure the encryption method and settings
    #[cfg(feature = "std")]
    pub fn encrypt(&self, bytes: &mut [u8]) -> DonutResult<Vec<u8>> {
        match self.provider {
            DonutCryptoProvider::Xor => {
                Ok(xor(bytes, &self.key))
            }
            DonutCryptoProvider::Aes => {
                aes256_cbc_encrypt(bytes, &self.key, &self.iv)
            }
            DonutCryptoProvider::None => Ok(bytes.to_vec()),
        }
    }

    /// Creates a new `DonutCrypto` object with the key and IV to use.
    /// **The key and IV must be valid vectors**
    pub fn new(key: Vec<u8>, iv: Vec<u8>, provider: DonutCryptoProvider) -> Self {
        Self { key, iv , provider}
    }

    /// Creates a new `DonutCrypto` object from using a hex key and IV
    /// This functions assumes the provider that will be used is Aes
    ///
    pub fn from_hex(key: &str, iv: &str) -> DonutResult<Self> {
        let key_bytes = from_hex(key)?;
        let iv_bytes = from_hex(iv)?;
        Ok(Self {
            key: key_bytes,
            iv: iv_bytes,
            provider: DonutCryptoProvider::Aes
        })
    }
}

/// Decryption helper to remove duplicate code warnings
pub fn decrypt_blob(mut decompressed_bytes: Vec<u8>) -> DonutResult<Vec<u8>> {
    crate::info!("decompressed_bytes.len()={}",decompressed_bytes.len());
    let prov = decompressed_bytes.pop().ok_or(DonutError::ParseFailed)?.into();
    let key_len = usize::from_be_bytes(pop_exact_vec::<8>(&mut decompressed_bytes)?);
    let iv_len = usize::from_be_bytes(pop_exact_vec::<8>(&mut decompressed_bytes)?);
    crate::info!("key len: {}", key_len);
    crate::info!("iv len: {}", iv_len);
    let key_bytes =  decompressed_bytes[..key_len].to_vec();
    let iv_bytes = decompressed_bytes[..iv_len].to_vec();
    let crypto = DonutCrypto::new(key_bytes, iv_bytes, prov);
    crate::info!("decrypting payload");
    crypto.decrypt(&decompressed_bytes)
}
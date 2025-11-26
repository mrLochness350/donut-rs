/// AES encryption and decryption utilities.
///
/// This module provides functions and structures to perform
/// symmetric encryption and decryption using the AES algorithm.
/// Typically used for secure payload handling or data protection.
pub mod aes;

/// Crypto helper functions
#[cfg(feature = "std")]
pub mod helpers;

/// Contains implementations for the [`DonutCrypto`](crypt::DonutCrypto) struct
pub mod crypt;
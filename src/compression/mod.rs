/// Native LZNT1 compression algorithm implementation
mod lznt1;
/// Native Xpress compression algorithm implementation
mod xpress;
/// Native GZIP/ZLIB compression algorithm implementation
mod inflate;

/// Compression helpers
#[cfg(feature = "std")]
pub mod compress;

/// Decompression helpers
pub mod decompress;

/// Enum definitions for [`CompressionEngine`](enums::CompressionEngine) and [`CompressionLevel`](enums::CompressionLevel)
pub mod enums;

#[cfg(feature = "std")]
pub use compress::compress;
pub use decompress::decompress_inner;
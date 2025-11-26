use alloc::vec::Vec;
use crate::compression::{inflate, lznt1, xpress};
use crate::compression::enums::{CompressionEngine, CompressionLevel};
use crate::types::structs::CompressionSettings;
use crate::errors::DonutResult;

/// Decompresses
#[unsafe(link_section = ".text")]
pub fn decompress_inner(settings: &CompressionSettings, bytes: &[u8]) -> DonutResult<Vec<u8>> {
    match settings.compression_engine {
        CompressionEngine::Gzip | CompressionEngine::Zlib => {
            inflate::decompress(bytes)
        }
        CompressionEngine::Lznt1 => {
            lznt1::decompress(bytes, settings.uncompressed_size as usize)
        }
        CompressionEngine::Xpress => {
            xpress::decompress(bytes, settings.uncompressed_size as usize)
        }
        CompressionEngine::None => {
            Ok(bytes.to_vec())
        }
    }
}

/// Decompression helper to remove duplicate code
#[unsafe(link_section = ".text")]
pub fn decompress(packed_bytes: &[u8], level: CompressionLevel, engine: CompressionEngine, uncompressed_size: usize) -> DonutResult<Vec<u8>> {
    if level != CompressionLevel::None {
        let mut settings = CompressionSettings::new(engine, level);
        settings.uncompressed_size = uncompressed_size as u64;
        decompress_inner(&settings, packed_bytes)
    } else {
        Ok(packed_bytes.to_vec())
    }
}


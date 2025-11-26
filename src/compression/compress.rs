use std::io::{BufReader, Read};
use azathoth_utils::crc32;
use flate2::bufread::{GzDecoder, GzEncoder, ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use crate::compression::enums::{CompressionEngine, CompressionLevel};
use crate::compression::xpress;
use crate::types::structs::CompressionSettings;
use crate::errors::{DonutError, DonutResult};

/// Compresses a given array of bytes with the specified [`CompressionSettings`] object
pub fn compress(settings: &mut CompressionSettings, data: &[u8]) -> DonutResult<Vec<u8>> {
    settings.uncompressed_size = data.len() as u64;
    let compressed = match settings.compression_engine {
        CompressionEngine::Gzip => GzipCompressor.compress(data, settings.compression_level.clone())?,
        CompressionEngine::Zlib => ZlibCompressor.compress(data, settings.compression_level.clone())?,
        CompressionEngine::None => data.to_vec(),
        CompressionEngine::Lznt1 => Lznt1Compressor.compress(data, settings.compression_level.clone())?,
        CompressionEngine::Xpress => xpress::compress(data)?,
    };

    settings.compressed_size = compressed.len() as u64;
    settings.compressed_crc = crc32(&compressed);
    Ok(compressed)
}

/// Decompresses a given array of bytes with the specified [`CompressionSettings`] object
pub fn decompress(settings: &mut CompressionSettings, data: &[u8]) -> DonutResult<Vec<u8>> {
    match settings.compression_engine {
        CompressionEngine::Gzip => Ok(GzipCompressor.decompress(data, settings.uncompressed_size as usize)?),
        CompressionEngine::Zlib => Ok(ZlibCompressor.decompress(data, settings.uncompressed_size as usize)?),
        CompressionEngine::None => Ok(data.to_vec()),
        CompressionEngine::Lznt1 => Ok(Lznt1Compressor.decompress(data, settings.uncompressed_size as usize)?),
        CompressionEngine::Xpress => Ok(XpressCompressor.decompress(data, settings.uncompressed_size as usize)?),
    }
}

trait Compressor {
    fn compress(&self, data: &[u8], level: CompressionLevel) -> DonutResult<Vec<u8>>;
    fn decompress(&self, data: &[u8], original_size: usize) -> DonutResult<Vec<u8>>;
}

struct GzipCompressor;
impl Compressor for GzipCompressor {
    fn compress(&self, data: &[u8], level: CompressionLevel) -> DonutResult<Vec<u8>> {
        let reader = BufReader::new(data);
        let c_level = level_to_compress(level);
        let mut gzip_encoder = GzEncoder::new(reader, c_level);
        let mut compressed_buffer = Vec::new();
        gzip_encoder.read_to_end(&mut compressed_buffer).map_err(|_|DonutError::CompressionFailure)?;
        Ok(compressed_buffer)
    }
    fn decompress(&self, data: &[u8], _original_size: usize) -> DonutResult<Vec<u8>> {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed_buffer = Vec::new();
        decoder.read_to_end(decompressed_buffer.as_mut()).map_err(|_|DonutError::CompressionFailure)?;
        Ok(decompressed_buffer)
    }
}

struct ZlibCompressor;
impl Compressor for ZlibCompressor {
    fn compress(&self, data: &[u8], level: CompressionLevel) -> DonutResult<Vec<u8>> {
        let reader = BufReader::new(data);
        let c_level = level_to_compress(level);
        let mut zlib_encoder = ZlibEncoder::new(reader, c_level);
        let mut compressed_buffer = Vec::new();
        zlib_encoder.read_to_end(&mut compressed_buffer).map_err(|_|DonutError::CompressionFailure)?;
        Ok(compressed_buffer)
    }
    fn decompress(&self, data: &[u8], _original_size: usize) -> DonutResult<Vec<u8>> {
        if !data.starts_with(&[0x78u8]) {
           return Err(DonutError::CompressionFailure);
        }
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed_buffer = Vec::new();
        decoder.read_to_end(decompressed_buffer.as_mut()).map_err(|_|DonutError::CompressionFailure)?;
        Ok(decompressed_buffer)
    }
}


fn level_to_compress(level: CompressionLevel) -> Compression {
    match level {
        CompressionLevel::None => Compression::none(),
        CompressionLevel::Normal => Compression::default(),
        CompressionLevel::Maximum => Compression::best()
    }
}

struct Lznt1Compressor;

impl Compressor for Lznt1Compressor {
    fn compress(&self, data: &[u8], _level: CompressionLevel) -> DonutResult<Vec<u8>> {
        crate::compression::lznt1::compress(data)
    }
    fn decompress(&self, data: &[u8], original_size: usize) -> DonutResult<Vec<u8>> {
        crate::compression::lznt1::decompress(data, original_size)
    }
}

struct XpressCompressor;
impl Compressor for XpressCompressor {
    fn compress(&self, data: &[u8], _level: CompressionLevel) -> DonutResult<Vec<u8>> {
        xpress::compress(data)
    }
    fn decompress(&self, data: &[u8], original_size: usize) -> DonutResult<Vec<u8>> {
        xpress::decompress(data, original_size)
    }
}
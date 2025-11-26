use alloc::vec::Vec;
use crate::errors::{DonutError, DonutResult};
#[cfg(feature = "std")]
const MAX_WINDOW_SIZE: usize = 65536;
const MIN_MATCH: usize = 3;

/// Decompresses a buffer with the Xpress compression algorithm
pub fn decompress(input: &[u8], decompressed_size: usize) -> DonutResult<Vec<u8>> {
    let mut output = Vec::with_capacity(decompressed_size);
    let mut input_pos = 0;
    while output.len() < decompressed_size {
        if input_pos + 4 > input.len() {
            break;
        }
        let flags = u32::from_le_bytes(input[input_pos..input_pos + 4].try_into().unwrap());
        input_pos += 4;
        for i in 0..32 {
            if output.len() >= decompressed_size {
                break;
            }
            if (flags >> i) & 1 == 1 {
                if input_pos >= input.len() {
                    return Err(DonutError::CompressionFailure);
                }
                output.push(input[input_pos]);
                input_pos += 1;
            } else {
                if input_pos + 2 > input.len() {
                    return Err(DonutError::CompressionFailure);
                }
                let phrase =
                    u16::from_le_bytes(input[input_pos..input_pos + 2].try_into().unwrap());
                input_pos += 2;
                let out_len = output.len();
                let offset_bits = if out_len > 1 {
                    (usize::BITS - (out_len - 1).leading_zeros()) as u16
                } else {
                    0
                }
                    .min(16);
                let length_bits = 16 - offset_bits;
                let length_mask = (1u16 << length_bits).saturating_sub(1);
                let length = (phrase & length_mask) as usize + MIN_MATCH;
                let offset = (phrase >> length_bits) as usize + 1;
                let start = out_len
                    .checked_sub(offset)
                    .ok_or(DonutError::CompressionFailure)?;
                for _ in 0..length {
                    if output.len() >= decompressed_size {
                        break;
                    }
                    let byte = *output
                        .get(start + (output.len() - start) % offset)
                        .ok_or(DonutError::CompressionFailure)?;
                    output.push(byte);
                }
            }
        }
    }
    if output.len() != decompressed_size {
        return Err(DonutError::CompressionFailure);
    }
    Ok(output)
}

/// Compresses a buffer with the Xpress compression algorithm
#[cfg(feature = "std")]
pub fn compress(input: &[u8]) -> DonutResult<Vec<u8>> {
    let mut compressed_data = Vec::new();
    let mut input_pos = 0;
    while input_pos < input.len() {
        let mut flags = 0u32;
        let mut phrases = Vec::with_capacity(68);
        let flag_pos = compressed_data.len();
        compressed_data.extend_from_slice(&[0, 0, 0, 0]);
        for i in 0..32 {
            if input_pos >= input.len() {
                break;
            }
            let window_start = input_pos.saturating_sub(MAX_WINDOW_SIZE);
            let mut best_match = (0, 0);
            if input.len() - input_pos >= MIN_MATCH {
                for j in (window_start..input_pos).rev() {
                    let mut current_len = 0;
                    while input_pos + current_len < input.len()
                        && j + current_len < input_pos
                        && input[j + current_len] == input[input_pos + current_len]
                        && current_len < 65538
                    {
                        current_len += 1;
                    }
                    if current_len > best_match.0 {
                        best_match = (current_len, input_pos - j);
                    }
                }
            }
            if best_match.0 >= MIN_MATCH {
                let (length, offset) = best_match;
                let offset_bits = if input_pos > 1 {
                    (usize::BITS - (input_pos - 1).leading_zeros()) as u16
                } else {
                    0
                }
                    .min(16);
                let length_bits = 16 - offset_bits;
                let length_mask = (1u16 << length_bits).saturating_sub(1);
                let capped_length = length.min(MIN_MATCH + length_mask as usize);
                let length_part = (capped_length - MIN_MATCH) as u16;
                let offset_part = if length_bits < 16 {
                    ((offset - 1) as u16) << length_bits
                } else {
                    0
                };
                let phrase = offset_part | length_part;
                phrases.extend_from_slice(&phrase.to_le_bytes());
                input_pos += capped_length;
            } else {
                flags |= 1 << i;
                phrases.push(input[input_pos]);
                input_pos += 1;
            }
        }
        compressed_data[flag_pos..flag_pos + 4].copy_from_slice(&flags.to_le_bytes());
        compressed_data.extend_from_slice(&phrases);
    }
    Ok(compressed_data)
}
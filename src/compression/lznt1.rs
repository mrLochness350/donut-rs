use alloc::vec::Vec;
use core::cmp::min;
use crate::errors::{DonutError, DonutResult};

const CHUNK_SIZE: usize = 4096;
const MIN_MATCH: usize = 3;

/// Decompresses a buffer with the lznt1 compression algorithm
pub fn decompress(input: &[u8], decompressed_size: usize) -> DonutResult<Vec<u8>> {
    let mut output = Vec::with_capacity(decompressed_size);
    let mut input_pos = 0;
    while input_pos < input.len() {
        if output.len() >= decompressed_size {
            break;
        }
        let header = u16::from_le_bytes(
            input
                .get(input_pos..input_pos + 2)
                .ok_or(DonutError::InvalidFormat)?
                .try_into()
                .unwrap(),
        );
        input_pos += 2;
        let chunk_size = (header & 0x0FFF) as usize + 1;
        let is_compressed = (header & 0x8000) != 0;
        if chunk_size > CHUNK_SIZE || input_pos + chunk_size > input.len() {
            return Err(DonutError::InvalidHeader);
        }
        if !is_compressed {
            let data_to_copy = min(chunk_size, decompressed_size - output.len());
            output.extend_from_slice(&input[input_pos..input_pos + data_to_copy]);
            input_pos += chunk_size;
        } else {
            let chunk_output_start = output.len();
            let chunk_end = input_pos + chunk_size;
            while input_pos < chunk_end && output.len() < decompressed_size {
                let tag = input.get(input_pos).ok_or(DonutError::InvalidFormat)?;
                input_pos += 1;
                for i in 0..8 {
                    if (tag >> i) as u32 & 1 == 0 { // TODO: check this works
                        if input_pos >= chunk_end || output.len() >= decompressed_size {
                            break;
                        }
                        let literal = input.get(input_pos).ok_or(DonutError::InvalidFormat)?;
                        output.push(*literal);
                        input_pos += 1;
                    } else {
                        if input_pos + 2 > chunk_end || output.len() >= decompressed_size {
                            break;
                        }
                        let phrase =
                            u16::from_le_bytes(input[input_pos..input_pos + 2].try_into().unwrap());
                        input_pos += 2;
                        let pos_in_chunk = output.len() - chunk_output_start;
                        let log2_pos = if pos_in_chunk > 0 {
                            31 - (pos_in_chunk as u32).leading_zeros()
                        } else {
                            0
                        };
                        let length_bits = (12 - log2_pos).min(15) as u16;
                        let length_mask = (1u16 << length_bits).saturating_sub(1);
                        let length = (phrase & length_mask) as usize + MIN_MATCH;
                        let offset = (phrase >> length_bits) as usize + 1;
                        let start = output
                            .len()
                            .checked_sub(offset)
                            .ok_or(DonutError::InvalidFormat)?;
                        for _ in 0..length {
                            if output.len() >= decompressed_size {
                                break;
                            }
                            let byte = *output
                                .get(start + (output.len() - start) % offset)
                                .ok_or(DonutError::InvalidFormat)?;
                            output.push(byte);
                        }
                    }
                }
            }
            input_pos = chunk_end;
        }
    }
    if output.len() != decompressed_size {
        return Err(DonutError::InvalidFormat);
    }
    Ok(output)
}

/// Compresses a buffer with the lznt1 compression algorithm
#[cfg(feature = "std")]
pub fn compress(input: &[u8]) -> DonutResult<Vec<u8>> {
    let mut compressed_data = Vec::new();
    for chunk in input.chunks(CHUNK_SIZE) {
        let mut compressed_chunk = Vec::new();
        let mut input_pos = 0;
        while input_pos < chunk.len() {
            let mut tag = 0u8;
            let mut phrases = Vec::with_capacity(1 + 8 * 2);
            let tag_pos = compressed_chunk.len();
            compressed_chunk.push(0);
            for i in 0..8 {
                if input_pos >= chunk.len() {
                    break;
                }
                let max_offset = min(input_pos, 0xFFF);
                let mut best_match = (0, 0);
                if chunk.len() - input_pos >= MIN_MATCH {
                    for offset in 1..=max_offset {
                        let mut current_len = 0;
                        let start = input_pos - offset;
                        while input_pos + current_len < chunk.len()
                            && chunk[start + current_len] == chunk[input_pos + current_len]
                            && current_len < 4098
                        {
                            current_len += 1;
                        }
                        if current_len > best_match.0 {
                            best_match = (current_len, offset);
                        }
                    }
                }
                if best_match.0 >= MIN_MATCH {
                    tag |= 1 << i;
                    let (length, offset) = best_match;
                    let log2_pos = if input_pos > 0 {
                        31 - (input_pos as u32).leading_zeros()
                    } else {
                        0
                    };
                    let length_bits = (12 - log2_pos).min(15) as u16;
                    let length_mask = (1u16 << length_bits).saturating_sub(1);
                    let capped_length = length.min(MIN_MATCH + length_mask as usize);
                    let length_part = (capped_length - MIN_MATCH) as u16;
                    let offset_part = ((offset - 1) as u16) << length_bits;
                    let phrase = offset_part | length_part;
                    phrases.extend_from_slice(&phrase.to_le_bytes());
                    input_pos += capped_length;
                } else {
                    phrases.push(chunk[input_pos]);
                    input_pos += 1;
                }
            }
            compressed_chunk[tag_pos] = tag;
            compressed_chunk.extend_from_slice(&phrases);
        }
        if compressed_chunk.len() < chunk.len() {
            let header = (0x8000 | 0x1000 | (compressed_chunk.len() - 1) as u16).to_le_bytes();
            compressed_data.extend_from_slice(&header);
            compressed_data.extend_from_slice(&compressed_chunk);
        } else {
            let header = (0x3000 | (chunk.len() - 1) as u16).to_le_bytes();
            compressed_data.extend_from_slice(&header);
            compressed_data.extend_from_slice(chunk);
        }
    }
    Ok(compressed_data)
}
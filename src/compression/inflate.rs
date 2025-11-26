use alloc::vec;
use alloc::vec::Vec;
use crate::errors::{DonutError, DonutResult};

struct InflateState<'a> {
    bit_buffer: u64,
    bit_count: u8,
    input: &'a [u8],
    input_pos: usize,
    pub output: Vec<u8>,
}

#[derive(Clone)]
struct HuffmanNode {
    value: u16,
    left: i16,
    right: i16,
}

const MAX_BITS: u8 = 16;
const GZIP_HEADER_FIRST: u8 = 0x1F;
const GZIP_HEADER_SECOND: u8 = 0x8B;

impl<'a> InflateState<'a> {
    #[unsafe(link_section = ".text")]
    fn new(input: &'a [u8]) -> Self {
        InflateState {
            bit_buffer: 0,
            bit_count: 0,
            input,
            input_pos: 0,
            output: Vec::new(),
        }
    }

    #[inline(always)]
    #[unsafe(link_section = ".text")]
    fn read_bits(&mut self, n: u8) -> DonutResult<u32> {
        while self.bit_count < n {
            if self.input_pos >= self.input.len() {
                return Err(DonutError::InvalidParameter);
            }
            self.bit_buffer |= (self.input[self.input_pos] as u64) << self.bit_count;
            self.input_pos += 1;
            self.bit_count += 8;
        }

        let result = (self.bit_buffer & ((1 << n) - 1)) as u32;
        self.bit_buffer >>= n;
        self.bit_count -= n;
        Ok(result)
    }

    #[unsafe(link_section = ".text")]
    fn build_huffman_tree(&self, lengths: &[u8]) -> DonutResult<Vec<HuffmanNode>> {
        let mut bl_count = [0u16; MAX_BITS as usize + 1];
        let mut max_bits = 0;
        for &len in lengths {
            if len > 0 {
                bl_count[len as usize] += 1;
                if len > max_bits {
                    max_bits = len;
                }
            }
        }

        bl_count[0] = 0;

        let mut next_code = [0u16; MAX_BITS as usize + 1];
        let mut code = 0;
        for bits in 1..=max_bits {
            code = (code + bl_count[(bits - 1) as usize]) << 1;
            next_code[bits as usize] = code;
        }
        let mut tree = Vec::with_capacity(lengths.len() * 2);
        tree.push(HuffmanNode {
            value: 0,
            left: -1,
            right: -1,
        });

        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }

            let code = next_code[len as usize];
            next_code[len as usize] += 1;

            let mut current_node_idx = 0;
            for bit in (0..len).rev() {
                let bit_val = (code >> bit) & 1;

                let next_node_idx = if bit_val == 0 {
                    let left_idx = tree[current_node_idx].left;
                    if left_idx == -1 {
                        let new_idx = tree.len() as i16;
                        tree.push(HuffmanNode {
                            value: 0,
                            left: -1,
                            right: -1,
                        });
                        tree[current_node_idx].left = new_idx;
                        new_idx
                    } else {
                        left_idx
                    }
                } else {
                    let right_idx = tree[current_node_idx].right;
                    if right_idx == -1 {
                        let new_idx = tree.len() as i16;
                        tree.push(HuffmanNode {
                            value: 0,
                            left: -1,
                            right: -1,
                        });
                        tree[current_node_idx].right = new_idx;
                        new_idx
                    } else {
                        right_idx
                    }
                };
                current_node_idx = next_node_idx as usize;
            }

            tree[current_node_idx].value = symbol as u16;
        }

        Ok(tree)
    }

    #[unsafe(link_section = ".text")]
    fn decode_symbol(&mut self, tree: &[HuffmanNode]) -> DonutResult<u16> {
        let mut current_node_idx = 0;
        loop {
            let bit = self.read_bits(1)?;
            let node = &tree[current_node_idx];

            let next_node_idx = if bit == 0 { node.left } else { node.right };

            if next_node_idx < 0 {
                return Err(DonutError::InvalidParameter);
            }

            let next_node = &tree[next_node_idx as usize];
            if next_node.left == -1 && next_node.right == -1 {
                return Ok(next_node.value);
            }
            current_node_idx = next_node_idx as usize;
        }
    }

    #[unsafe(link_section = ".text")]
    fn handle_uncompressed_block(&mut self) -> DonutResult<()> {
        self.bit_buffer = 0;
        self.bit_count = 0;

        if self.input_pos + 4 > self.input.len() {
            return Err(DonutError::InvalidParameter);
        }

        let len = u16::from_le_bytes([self.input[self.input_pos], self.input[self.input_pos + 1]])
            as usize;
        let nlen = u16::from_le_bytes([
            self.input[self.input_pos + 2],
            self.input[self.input_pos + 3],
        ]);
        self.input_pos += 4;

        if len as u16 != !nlen {
            return Err(DonutError::InvalidParameter);
        }

        if self.input_pos + len > self.input.len() {
            return Err(DonutError::InvalidParameter);
        }

        self.output
            .extend_from_slice(&self.input[self.input_pos..self.input_pos + len]);
        self.input_pos += len;
        Ok(())
    }

    #[unsafe(link_section = ".text")]
    fn build_static_huffman_trees(
        &self,
    ) -> DonutResult<(Vec<HuffmanNode>, Vec<HuffmanNode>)> {
        let mut lit_len_lengths = [0u8; 288];
        lit_len_lengths[..144].fill(8);
        lit_len_lengths[144..256].fill(9);
        lit_len_lengths[256..280].fill(7);
        lit_len_lengths[280..288].fill(8);

        let dist_lengths = [5u8; 32];

        let lit_len_tree = self.build_huffman_tree(&lit_len_lengths)?;
        let dist_tree = self.build_huffman_tree(&dist_lengths)?;

        Ok((lit_len_tree, dist_tree))
    }

    #[unsafe(link_section = ".text")]
    fn read_dynamic_huffman_trees(
        &mut self,
    ) -> DonutResult<(Vec<HuffmanNode>, Vec<HuffmanNode>)> {
        let hlit = self.read_bits(5)? as usize + 257;
        let hdist = self.read_bits(5)? as usize + 1;
        let hclen = self.read_bits(4)? as usize + 4;

        let mut code_lengths_alphabet = [0u8; 19];

        let order = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        for i in 0..hclen {
            code_lengths_alphabet[order[i]] = self.read_bits(3)? as u8;
        }

        let code_tree = self.build_huffman_tree(&code_lengths_alphabet)?;

        let mut all_lengths = vec![0u8; hlit + hdist];
        let mut i = 0;
        while i < all_lengths.len() {
            let symbol = self.decode_symbol(&code_tree)?;
            match symbol {
                0..=15 => {
                    all_lengths[i] = symbol as u8;
                    i += 1;
                }
                16 => {
                    if i == 0 {
                        return Err(DonutError::InvalidParameter);
                    }
                    let prev = all_lengths[i - 1];
                    let repeat = self.read_bits(2)? as usize + 3;
                    if i + repeat > all_lengths.len() {
                        return Err(DonutError::InvalidParameter);
                    }
                    for _ in 0..repeat {
                        all_lengths[i] = prev;
                        i += 1;
                    }
                }
                17 => {
                    let repeat = self.read_bits(3)? as usize + 3;
                    if i + repeat > all_lengths.len() {
                        return Err(DonutError::InvalidParameter);
                    }

                    i += repeat;
                }
                18 => {
                    let repeat = self.read_bits(7)? as usize + 11;
                    if i + repeat > all_lengths.len() {
                        return Err(DonutError::InvalidParameter);
                    }
                    i += repeat;
                }
                _ => return Err(DonutError::InvalidParameter),
            }
        }

        let lit_len_tree = self.build_huffman_tree(&all_lengths[..hlit])?;
        let dist_tree = self.build_huffman_tree(&all_lengths[hlit..])?;

        Ok((lit_len_tree, dist_tree))
    }

    #[unsafe(link_section = ".text")]
    fn inflate_huffman_block(
        &mut self,
        lit_len_tree: &[HuffmanNode],
        dist_tree: &[HuffmanNode],
    ) -> DonutResult<()> {
        const LENGTH_BASE: [u16; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const LENGTH_EXTRA: [u8; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DIST_BASE: [u16; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        const DIST_EXTRA: [u8; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];

        loop {
            let symbol = self.decode_symbol(lit_len_tree)?;
            match symbol {
                0..=255 => self.output.push(symbol as u8),
                256 => break,
                257..=285 => {
                    let length_idx = (symbol - 257) as usize;
                    let extra_bits = self.read_bits(LENGTH_EXTRA[length_idx])?;
                    let length = LENGTH_BASE[length_idx] as u32 + extra_bits;

                    let dist_symbol = self.decode_symbol(dist_tree)?;
                    if dist_symbol > 29 {
                        return Err(DonutError::InvalidParameter);
                    }

                    let dist_idx = dist_symbol as usize;
                    let extra_dist_bits = self.read_bits(DIST_EXTRA[dist_idx])?;
                    let distance = DIST_BASE[dist_idx] as u32 + extra_dist_bits;

                    let out_len = self.output.len();
                    if distance as usize > out_len {
                        return Err(DonutError::InvalidParameter);
                    }

                    self.output.reserve(length as usize);
                    for i in 0..length {
                        let copy_pos = out_len - distance as usize + i as usize;
                        let byte = self.output[copy_pos];
                        self.output.push(byte);
                    }
                }
                _ => return Err(DonutError::InvalidParameter),
            }
        }
        Ok(())
    }
}

/// Decompresses a byte buffer
///
/// This function expects a valid GZIP/ZLIB blob, otherwise it will fail
#[unsafe(link_section = ".text")]
pub fn decompress(input: &[u8]) -> DonutResult<Vec<u8>> {
    if input.len() < 2 {
        return Err(DonutError::InvalidHeader);
    }

    let mut state = InflateState::new(input);

    let is_gzip = state.input[0] == GZIP_HEADER_FIRST && state.input[1] == GZIP_HEADER_SECOND;

    if is_gzip {
        if state.input.len() < 10 {
            return Err(DonutError::InvalidHeader);
        }
        let flags = state.input[3];
        state.input_pos = 10;

        if flags & 0x04 != 0 {
            if state.input_pos + 2 > state.input.len() {
                return Err(DonutError::InvalidParameter);
            }
            let xlen = u16::from_le_bytes([
                state.input[state.input_pos],
                state.input[state.input_pos + 1],
            ]) as usize;
            state.input_pos += 2 + xlen;
        }

        if flags & 0x08 != 0 {
            while state.input_pos < state.input.len() && state.input[state.input_pos] != 0 {
                state.input_pos += 1;
            }
            state.input_pos += 1;
        }

        if flags & 0x10 != 0 {
            while state.input_pos < state.input.len() && state.input[state.input_pos] != 0 {
                state.input_pos += 1;
            }
            state.input_pos += 1;
        }

        if flags & 0x02 != 0 {
            state.input_pos += 2;
        }
    } else {
        let cmf = state.input[0];
        let flg = state.input[1];

        if (cmf & 0x0F) != 8 || (cmf >> 4) > 7 {
            return Err(DonutError::InvalidFormat);
        }

        if !((cmf as u16) * 256 + (flg as u16)).is_multiple_of(31) {
            return Err(DonutError::InvalidHeader);
        }

        if (flg & 0x20) != 0 {
            return Err(DonutError::InvalidFormat);
        }

        state.input_pos = 2;
    }

    loop {
        let is_final_block = state.read_bits(1)? == 1;
        let block_type = state.read_bits(2)?;

        match block_type {
            0 => state.handle_uncompressed_block()?,
            1 => {
                let (lit_len_tree, dist_tree) = state.build_static_huffman_trees()?;
                state.inflate_huffman_block(&lit_len_tree, &dist_tree)?;
            }
            2 => {
                let (lit_len_tree, dist_tree) = state.read_dynamic_huffman_trees()?;
                state.inflate_huffman_block(&lit_len_tree, &dist_tree)?;
            }
            _ => return Err(DonutError::InvalidParameter),
        }

        if is_final_block {
            break;
        }
    }

    Ok(state.output)
}
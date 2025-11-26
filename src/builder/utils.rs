use std::cmp;
use crate::errors::{DonutError, DonutResult};
use crate::fs::pe::to_pe;
use crate::prelude::loader_win::LOADER_WINDOWS;

pub fn patch_marker(buf: &mut [u8], pattern: &[u8], replacement: &[u8]) -> DonutResult<()> {
    if pattern.len() != replacement.len() {
        return Err(DonutError::BuildError("mismatched lengths".into()));
    }

    if let Some(pos) = find_offset(buf, pattern)? {
        buf[pos..pos + pattern.len()].copy_from_slice(replacement);
        Ok(())
    } else {
        Err(DonutError::BuildError("failed to find marker".into()))
    }
}

pub fn find_offset(buf: &[u8], pattern: &[u8]) -> DonutResult<Option<usize>> {
    Ok(buf
        .windows(pattern.len())
        .position(|window| window == pattern))
}


pub fn extract_info() -> DonutResult<(Vec<u8>, usize)> {
    let (pe, loader_bytes) = (to_pe(&LOADER_WINDOWS)?, LOADER_WINDOWS.to_vec());
    let text_section = pe
        .sections
        .iter()
        .find(|&s| s.name().unwrap() == ".text")
        .ok_or_else(|| DonutError::BuildError("Failed to find .text section in loader".into()))?;

    let text_va = text_section.virtual_address as usize;
    let text_raw = text_section.pointer_to_raw_data as usize;
    let text_size = cmp::max(text_section.virtual_size, text_section.size_of_raw_data) as usize;
    let text_bytes = loader_bytes
        .get(text_raw..text_raw + text_size)
        .ok_or_else(|| DonutError::BuildError("Invalid section range in loader".into()))?
        .to_vec();
    let optional_header = pe.header.optional_header.ok_or_else(|| DonutError::BuildError("failed to get optional header".into()))?;
    let entry_rva = optional_header.standard_fields.address_of_entry_point as usize;
    let entry_offset = entry_rva.checked_sub(text_va).ok_or_else(|| DonutError::BuildError("entry offset outside of .text section".into()))?;
    Ok((text_bytes, entry_offset))
}


pub fn build_stub_bootstrap(stub_bytes: &[u8]) -> DonutResult<Vec<u8>> {
    let stub_size = stub_bytes.len() as u32;
    let mut packed_vector = Vec::with_capacity(4 + stub_bytes.len());
    packed_vector.extend_from_slice(&stub_size.to_le_bytes());
    packed_vector.extend_from_slice(stub_bytes);

    Ok(packed_vector)
}
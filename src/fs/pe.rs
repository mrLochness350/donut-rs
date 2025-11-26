use az_logger::error;
use goblin::{
    Object,
    pe::{PE, section_table::SectionTable},
};

use crate::errors::{DonutError, DonutResult};
use crate::utils::globals::bytes_to_str;

pub(crate) fn get_target_pe_section(pe: &PE, section_name: String) -> DonutResult<SectionTable> {
    Ok(pe
        .sections
        .iter()
        .find(|s| bytes_to_str(&s.name) == section_name.as_str())
        .ok_or(DonutError::ParseFailed)?
        .clone())
}

pub(crate) fn to_pe(bytes: &[u8]) -> DonutResult<PE<'_>> {
    let p = match Object::parse(bytes).map_err(|e| DonutError::Unknown {e: e.to_string()})? {
        Object::PE(pe) => pe,
        Object::Unknown(u) => {
            error!("File is not a PE file: {:#04x}", u);
            return Err(DonutError::InvalidFormat)
        },
        _ => return Err(DonutError::Unknown {e: "File is not a PE file".to_string() })
    };
    Ok(p)
}

pub(crate) fn extract_pe_section_data(
    pe: &PE,
    section_name: String,
    bytes: &[u8],
) -> DonutResult<Vec<u8>> {
    let section = get_target_pe_section(pe, section_name)?;
    let rva = section.virtual_address;
    let size = section.virtual_size;
    let start = rva_to_offset(pe, rva)? as usize;
    let end = start.checked_add(size as usize).ok_or(DonutError::ParseFailed)?;

    if end > bytes.len() {
        error!("File bytes is smaller than the section size");
        return Err(DonutError::ParseFailed);
    }
    Ok(bytes[start..end].to_vec())
}


pub(crate) fn rva_to_offset(pe: &PE, rva: u32) -> DonutResult<u32> {
    for section in &pe.sections {
        let va = section.virtual_address;
        let size = section.size_of_raw_data;
        if rva >= va && rva < va + size {
            let offset = section.pointer_to_raw_data + (rva - va);
            return Ok(offset)
        }
    }
    Err(DonutError::ParseFailed)
}

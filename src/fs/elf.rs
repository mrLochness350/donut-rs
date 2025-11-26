use az_logger::{error, info, warn};
use goblin::elf::Elf;


/// Struct to help with parsing and mapping an ELF file into memory
#[repr(C, packed)]
pub struct BinInfo {
    /// Address of the `_start` function
    pub start_function: u64,
    /// Address of the dynamic linker pointer
    pub dynamic_linker_info: u64,
    /// BIN magic number
    pub magic_number: [u8; 4],
}

const BIN_MAGIC_NUMBER: [u8; 4] = [0x7f, b'B', b'I', b'N'];
const ENTRYPOINT: &str = "_start";

/// Attempts to map an ELF file into memory
pub fn map_elf(data: &[u8]) -> Option<Vec<u8>> {
    let elf = Elf::parse(data).ok()?;
    let mut mapping = vec![0u8; 0x1000000];
    let mut used = 0usize;

    let mut bin_info = BinInfo {
        start_function: 0,
        dynamic_linker_info: 0,
        magic_number: BIN_MAGIC_NUMBER,
    };

    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    for ph in &elf.program_headers {
        match ph.p_type {
            PT_LOAD => {
                let source = &data[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize];
                let dest = &mut mapping[ph.p_vaddr as usize..(ph.p_vaddr + ph.p_filesz) as usize];

                info!(
                    "memcpy({:p}, {:p}, {:08x})",
                    dest.as_ptr(),
                    source.as_ptr(),
                    ph.p_filesz
                );

                dest.copy_from_slice(source);
                used = (ph.p_memsz + ph.p_vaddr) as usize;
            }
            PT_DYNAMIC => {
                bin_info.dynamic_linker_info = ph.p_vaddr;
            }
            _ => {}
        }
    }


    let (syms, strtab) = if !elf.syms.is_empty() {
        (&elf.syms, &elf.strtab)
    } else if !elf.dynsyms.is_empty() {
        (&elf.dynsyms, &elf.dynstrtab)
    } else {
        error!("No symbol tables found!");
        return None;
    };

    for sym in syms {
        if let Some(name) = strtab.get_at(sym.st_name) {
            // debug!("Name: {}", name);
            if name == ENTRYPOINT {
                bin_info.start_function = sym.st_value;
                break;
            }
        } else {
            warn!("Could not find name symbol for offset: 0x{:x}", sym.st_value);
        }
    }

    if bin_info.start_function == 0 {
        error!("Unable to locate entry point '{}'", ENTRYPOINT);
        return None;
    }

    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            &bin_info as *const BinInfo as *const u8,
            size_of::<BinInfo>(),
        )
    };
    mapping[used..used + info_bytes.len()].copy_from_slice(info_bytes);
    used += info_bytes.len();

    mapping.truncate(used);
    Some(mapping)
}

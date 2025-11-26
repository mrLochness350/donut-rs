#![allow(non_snake_case, non_camel_case_types)]

/// Represents the ELF64 file header.
///
/// Contains metadata about the ELF executable, including entry point,
/// program header table, and section header table offsets.
#[repr(C)]
#[derive(Debug)]
pub struct Elf64Ehdr {
    /// Identification bytes (magic number, class, data encoding, etc.).
    pub e_ident: [u8; 16],
    /// Object file type (e.g., ET_EXEC, ET_DYN).
    pub e_type: u16,
    /// Target machine architecture (e.g., EM_X86_64).
    pub e_machine: u16,
    /// ELF version.
    pub e_version: u32,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// File offset of the program header table.
    pub e_phoff: u64,
    /// File offset of the section header table.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size in bytes.
    pub e_ehsize: u16,
    /// Size of each program header entry.
    pub e_phentsize: u16,
    /// Number of entries in the program header table.
    pub e_phnum: u16,
    /// Size of each section header entry.
    pub e_shentsize: u16,
    /// Number of entries in the section header table.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

/// Represents an ELF64 dynamic table entry.
///
/// Used in shared objects and executables to describe dynamic linking information.
#[repr(C)]
#[derive(Debug)]
pub struct Elf64Dyn {
    /// Dynamic entry type (e.g., DT_NEEDED, DT_SYMTAB).
    pub d_tag: i64,
    /// Value associated with the tag (address or integer).
    pub d_val: u64,
}

/// Represents an ELF64 relocation entry with addend.
///
/// Describes how a symbol or address should be relocated at runtime.
#[repr(C)]
#[derive(Debug)]
pub struct Elf64Rela {
    /// Location to apply the relocation.
    pub r_offset: u64,
    /// Addend constant used in the relocation calculation.
    pub r_addend: i64,
    /// Relocation type and symbol index, packed.
    pub r_info: u64,
}

/// Represents an ELF64 symbol table entry.
///
/// Used to store symbol information such as function and variable names and addresses.
#[repr(C)]
#[derive(Debug)]
pub struct Elf64Sym {
    /// Index into the string table for the symbol's name.
    pub st_name: u32,
    /// Symbol's type and binding attributes.
    pub st_info: u8,
    /// Symbol's visibility.
    pub st_other: u8,
    /// Section index where the symbol is defined.
    pub st_shndx: u16,
    /// Symbol's value or address.
    pub st_value: u64,
    /// Size of the symbol in bytes.
    pub st_size: u64,
}

/// Represents an ELF64 program header table entry.
///
/// Describes a segment of the program to be loaded into memory.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Elf64Phdr {
    /// Segment type (e.g., PT_LOAD, PT_DYNAMIC).
    pub p_type: u32,
    /// Segment flags (e.g., executable, writable).
    pub p_flags: u32,
    /// File offset of the segment.
    pub p_offset: u64,
    /// Virtual address where the segment is loaded.
    pub p_vaddr: u64,
    /// Physical address (usually ignored on modern systems).
    pub p_paddr: u64,
    /// Size of the segment in the file.
    pub p_filesz: u64,
    /// Size of the segment in memory.
    pub p_memsz: u64,
    /// Alignment constraints for this segment.
    pub p_align: u64,
}

/// Represents an ELF64 section header table entry.
///
/// Describes individual sections within the ELF file.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Elf64Shdr {
    /// Index into the section name string table.
    pub sh_name: usize,
    /// Section type (e.g., SHT_PROGBITS, SHT_SYMTAB).
    pub sh_type: u32,
    /// Section flags (e.g., SHF_ALLOC, SHF_EXECINSTR).
    pub sh_flags: u64,
    /// Virtual address of the section in memory.
    pub sh_addr: u64,
    /// File offset of the section.
    pub sh_offset: u64,
    /// Size of the section in bytes.
    pub sh_size: u64,
    /// Section header table link index.
    pub sh_link: u32,
    /// Additional section-specific information.
    pub sh_info: u32,
    /// Section alignment constraints.
    pub sh_addralign: u64,
    /// Size of entries in the section (if it holds a table).
    pub sh_entsize: u64,
}

use goblin::Object;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::types::enums::OutputFormat;
use crate::errors::{DonutError, DonutResult};
use crate::fs::elf::map_elf;
use crate::fs::pe::{extract_pe_section_data, to_pe};
use crate::utils::formatters::format_bytes;
use crate::utils::globals::{create_file, default_file_name};

enum FileType {
    PE,
    Elf,
    Raw,
}

/// Helper struct for converting a binary to a vector of bytes
pub struct BinaryConverter {
    is_64: bool,
    output_file: Option<String>,
    file_bytes: Vec<u8>,
    output_format: OutputFormat,
    target_section: String,
    file_type: FileType,
    filename: String,
    formatted_bytes: Vec<u8>,
    dump_raw: bool,
    variable_name: Option<String>,
}

impl BinaryConverter {

    fn parse_file(
        input_file: PathBuf,
        output_file: Option<String>,
        target_section: Option<String>,
        output_format: OutputFormat,
        dump_raw: bool,
        variable_name: Option<String>,
    ) -> DonutResult<Self> {
        let file_bytes = fs::read(&input_file).map_err(|e| DonutError::Io(e.to_string()))?;
        let filename = input_file
            .file_name()
            .ok_or_else(|| {
                az_logger::error!("Failed to get file name");
                DonutError::ParseFailed
            })?
            .to_str()
            .ok_or_else(|| {
                az_logger::error!("Failed to convert filename to string");
                DonutError::ParseFailed
            })?
            .to_string();
        let (file_type, is_64) =
            match Object::parse(&file_bytes).map_err(|e| DonutError::Io(e.to_string()))? {
                Object::PE(pe) => (FileType::PE, pe.is_64),
                Object::Elf(elf) => (FileType::Elf, elf.is_64),
                _ => (FileType::Raw, false),
            };
        let section = if let Some(sect) = &target_section {
            sect.to_string()
        } else {
            ".text".to_string()
        };
        Ok(Self {
            is_64,
            output_file,
            file_bytes,
            output_format,
            target_section: section,
            filename,
            file_type,
            formatted_bytes: Vec::new(),
            dump_raw,
            variable_name,
        })
    }

    /// Creates a new [`BinaryConverter`] object
    pub fn new(
        file: impl Into<PathBuf>,
        output_file: Option<String>,
        target_section: Option<String>,
        output_format: OutputFormat,
        dump_raw: bool,
        variable_name: Option<String>,
    ) -> DonutResult<Self> {
        let input_file = file.into();
        if !input_file.exists() {
            return Err(DonutError::NotFound(format!("could not find given file: '{}'", input_file.display())));
        };
        Self::parse_file(input_file, output_file, target_section, output_format, dump_raw, variable_name)
    }

    /// Converts the input file to the formatted bytes
    pub fn convert(&mut self) -> DonutResult<()> {
        let bytes = if self.dump_raw {
            self.dump_raw()?
        } else {
            self.extract_section_data()?
        };
        let formatted_bytes = if self.output_format == OutputFormat::Raw {
            bytes
        } else {
            let formatted_bytes = format_bytes(&bytes, self.output_format.clone(), self.variable_name.clone())?;
            formatted_bytes.as_bytes().to_vec()
        };
        self.formatted_bytes = formatted_bytes;
        Ok(())
    }

    /// Saves the file to disk
    ///
    /// Uses the output path stored in the [`BinaryConverter`] struct
    pub fn save_file(&self) -> DonutResult<()> {
        if let Some(out) = &self.output_file {
            let mut file = create_file(out)?;
            file.write(&self.formatted_bytes)
                .map_err(|e| DonutError::Io(e.to_string()))?;
        } else {
            let arch = if self.is_64 { "x64" } else { "x86" }; //very basic
            let file_name = format!(
                "{}_{}",
                arch,
                default_file_name(self.filename.as_str(), self.output_format.clone())
            );
            let mut file = create_file(&file_name)?;
            file.write(&self.formatted_bytes)
                .map_err(|e| DonutError::Io(e.to_string()))?;
        }
        Ok(())
    }

    fn extract_section_data(&self) -> DonutResult<Vec<u8>> {
        let bytes: Vec<u8> = match self.file_type {
            FileType::PE => {
                let pe = to_pe(&self.file_bytes)?;
                extract_pe_section_data(&pe, self.target_section.clone(), &self.file_bytes)?
            }
            FileType::Elf => {
                map_elf(&self.file_bytes).ok_or(DonutError::Other("Failed to parse elf".to_string()))?
            }
            FileType::Raw => self.file_bytes.clone(),
        };
        Ok(bytes)
    }

    fn dump_raw(&self) -> DonutResult<Vec<u8>> {
        Ok(self.file_bytes.clone())
    }
}
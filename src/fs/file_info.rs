use std::fs;
use std::path::PathBuf;
use goblin::Object;
use serde::{Deserialize, Serialize};
use crate::types::enums::{Arch, DonutValidFileType};
use crate::types::structs::DotnetParameters;
use crate::utils::globals::extract_dotnet_runtime_version;
use crate::errors::{DonutError, DonutResult};

/// Struct to store information about the embedded file
#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileInfo {
    #[serde(skip_serializing)]
    pub(crate) filename: String,
    pub(crate) size: usize,
    pub(crate) arch: Arch,
    pub(crate) file_bytes: Vec<u8>,
    pub(crate) file_type: DonutValidFileType,
    pub(crate) dotnet_parameters: Option<DotnetParameters>,
    pub(crate) entry: u32,
}

impl FileInfo {
    fn parse_file(bytes: &mut [u8], filename: String) -> DonutResult<Self> {
        let b= bytes.to_vec();
        let obj = Object::parse(&b).map_err(|e| DonutError::GoblinError(e.to_string()))?;
        let file_size = bytes.len();
        let val = match obj {
            Object::Elf(elf) => Self {
                filename,
                size: file_size,
                arch: if elf.is_64 { Arch::X64 } else { Arch::X86 },
                file_type: if elf.is_lib {
                    DonutValidFileType::SharedObject
                } else {
                    DonutValidFileType::ELF
                },
                file_bytes: bytes.to_vec(),
                dotnet_parameters: None,
                entry: elf.entry as u32
            },

            Object::PE(pe) => {
                let (version, is_dotnet) = match extract_dotnet_runtime_version(&pe, bytes) {
                    Ok(v) => (v, true),
                    Err(DonutError::InvalidFormat) => (String::new(), false),
                    Err(e) => return Err(e),
                };
                Self {
                    filename,
                    size: file_size,
                    arch: if pe.is_64 { Arch::X64 } else { Arch::X86 },
                    file_type: if pe.is_lib {
                        DonutValidFileType::Dll { dotnet: is_dotnet }
                    } else {
                        DonutValidFileType::PE { dotnet: is_dotnet }
                    },
                    file_bytes: bytes.to_vec(),
                    dotnet_parameters: is_dotnet.then_some(DotnetParameters {
                        runtime: version.clone(),
                        version,
                        ..Default::default()
                    }),
                    entry: pe.entry
                }
            }
            _ => {
                return Err(DonutError::InvalidFormat)
            },
        };
        Ok(val)
    }
    /// Create a new [`FileInfo`] object from a path
    pub fn from_path(path: impl Into<PathBuf>) -> DonutResult<Self> {
        let path = path.into();
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or(DonutError::ParseFailed)?
            .to_string();
        let mut file_bytes = fs::read(&path).map_err(|e| {
            DonutError::Io(e.to_string())
        })?;
        Self::parse_file(&mut file_bytes, filename)
    }
}

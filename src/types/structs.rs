use super::enums::{AmsiBypassTechnique, EtwBypassTechnique};
use crate::errors::DonutError;
use crate::utils::globals::gen_rand_byte_array;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use azathoth_utils::codec::{Codec, Decoder, Encoder};
use azathoth_utils::errors::AzUtilResult;
use core::str::FromStr;
use crate::compression::enums::{CompressionEngine, CompressionLevel};
/// Represents a 128-bit globally unique identifier (GUID).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct Guid {
    /// First 32 bits of the GUID.
    pub data1: u32,
    /// Next 16 bits of the GUID.
    pub data2: u16,
    /// Next 16 bits of the GUID.
    pub data3: u16,
    /// Final 64 bits of the GUID as bytes.
    pub data4: [u8; 8],
}

impl Guid {
    /// Creates a new GUID from its four components.
    pub const fn new(
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    ) -> Self {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Converts a 128-bit integer to a GUID (big-endian order).
    pub const fn from_u128(data: u128) -> Self {
        let bytes = data.to_be_bytes();

        Guid {
            data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_be_bytes([bytes[4], bytes[5]]),
            data3: u16::from_be_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ],
        }
    }
}

impl Codec for Guid {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u32(self.data1)?;
        enc.push_u16(self.data2)?;
        enc.push_u16(self.data3)?;
        enc.push_slice(&self.data4)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        let data1 = dec.read_u32()?;
        let data2 = dec.read_u16()?;
        let data3 = dec.read_u16()?;
        let data4: Vec<u8> = dec.read_vec()?;
        Ok(Self {
            data1,
            data2,
            data3,
            data4: data4.try_into().unwrap()
        })
    }
}

/// Amsi AV bypass settings
/// Contains the optional junk data to use when bypassing Amsi, and the technique used to bypass it
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct AmsiBypass {
    injected_trash_data: Option<Vec<u8>>,
    amsi_bypass_technique: AmsiBypassTechnique
}

impl Codec for AmsiBypass {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.injected_trash_data.encode(enc)?;
        self.amsi_bypass_technique.encode(enc)?;
        Ok(())

    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        Ok(Self {
            injected_trash_data: dec.read_opt()?,
            amsi_bypass_technique: AmsiBypassTechnique::decode(dec)?,
        })
    }
}


/// ETW bypass settings
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct EtwBypass {
    etw_bypass_technique: EtwBypassTechnique
}

impl Codec for EtwBypass {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.etw_bypass_technique.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        Ok(Self {
            etw_bypass_technique: EtwBypassTechnique::decode(dec)?,
        })
    }
}

/// Antivirus AV bypass options for the loader
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct AvBypassOptions {
    /// Optional settings to attempt an AMSI bypass
    pub amsi_bypass: Option<AmsiBypass>,
    /// Optional settings to attempt an Etw bypass
    pub etw_bypass: Option<EtwBypass>,
    /// Attempts to figure out if a syscall hook exists and will try to bypass it
    pub patch_syscall_gate: bool,
}

impl Codec for AvBypassOptions {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.amsi_bypass.encode(enc)?;
        self.etw_bypass.encode(enc)?;
        enc.push_bool(self.patch_syscall_gate)?;
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            amsi_bypass: dec.read_opt()?,
            etw_bypass: dec.read_opt()?,
            patch_syscall_gate: dec.read_bool()?,
        })
    }
}
impl AvBypassOptions {
    /// Creates a new AV bypass object for the loader to use when loading the instance
    pub fn new(patch_syscall_gate: bool,etw_bypass_technique: EtwBypassTechnique, amsi_bypass_technique: AmsiBypassTechnique, amsi_gen_trash: bool) -> Self {
        let etw_bypass = if etw_bypass_technique != EtwBypassTechnique::None {
            Some(EtwBypass::new(etw_bypass_technique))
        } else {
            None
        };
        let amsi_bypass = if amsi_bypass_technique != AmsiBypassTechnique::None {
            Some(AmsiBypass::new(amsi_bypass_technique, amsi_gen_trash))
        } else {
            None
        };
        Self {
            amsi_bypass,
            etw_bypass,
            patch_syscall_gate,
        }
    }
}


impl AmsiBypass {
    /// Creates a new [`AmsiBypass`] object with the given technique.
    ///
    /// The `generate_trash` parameter may be removed in favor of forcing the generation of a random array of bytes, or a hardcoded byte buffer
    pub fn new(amsi_bypass_technique: AmsiBypassTechnique, generate_trash: bool) -> Self {
        let trash = if generate_trash {
            Some(gen_rand_byte_array(6))
        } else {
            None
        };
        Self {
            injected_trash_data: trash,
            amsi_bypass_technique
        }
    }
}

impl EtwBypass {
    /// **THIS MAY BE CHANGED/REMOVED COMPLETELY IN THE FUTURE**
    /// Creates a new [`EtwBypass`] object with the given bypass technique.
    #[allow(unused)]
    pub fn new(etw_bypass_technique: EtwBypassTechnique) -> Self {
        Self {
            etw_bypass_technique
        }
    }
}

impl FromStr for EtwBypassTechnique {
    type Err = DonutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "patch_event_write" => Ok(Self::PatchEtwEventWrite),
            "disable_tracing" => Ok(Self::EtwDisableTracing),
            "none" => Ok(Self::None),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}

/// (De)Compression settings for the loader and builder to use
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct CompressionSettings {
    /// Compression engine to use. Refer to the [`CompressionEngine`] documentation for possible values
    pub compression_engine: CompressionEngine,
    /// Size of the data after the compression operation
    pub compressed_size: u64,
    /// Compression level to use. This is for ZLib/GZip compression. Refer to the [`CompressionLevel`] documentation for possible values
    pub compression_level: CompressionLevel,
    /// Tracker for the uncompressed size of the data
    pub uncompressed_size: u64,
    /// Tracker for the crc32 value of the compressed data
    pub compressed_crc: u32,
}

impl Codec for CompressionSettings {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.compression_engine.encode(enc)?;
        self.compressed_size.encode(enc)?;
        self.compression_level.encode(enc)?;
        self.uncompressed_size.encode(enc)?;
        self.compressed_crc.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        Ok(Self {
            compression_engine: CompressionEngine::decode(dec)?,
            compressed_size: dec.read_u64()?,
            compression_level: CompressionLevel::decode(dec)?,
            uncompressed_size: dec.read_u64()?,
            compressed_crc: dec.read_u32()?,
        })
    }
}

impl CompressionSettings {
    /// Creates a new [`CompressionSettings`] object
    pub fn new(compression_engine: CompressionEngine, compression_level: CompressionLevel) -> Self {
        Self {
            compression_level,
            compression_engine,
            compressed_size: 0,
            uncompressed_size: 0,
            compressed_crc: 0,
        }
    }
}


/// Function VTable struct
///
/// Stores the function name hashes and the seed used to hash them for the loader to be able to dynamically resolve them without using static strings
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct ApiTable {
    /// Vector for storing function hashes
    pub hashes: Vec<u32>,
    /// Seed value used to hash the functions
    pub seed: u32,
    /// Windows functions VTable
    #[cfg(feature="loader")]
    #[cfg_attr(feature="std", serde(skip))]
    #[cfg(target_os="windows")]
    pub windows_funcs: crate::platform::windows::fn_defs::WinApi,
    /// Linux functions VTable
    #[cfg(feature="loader")]
    #[cfg_attr(feature="std", serde(skip))]
    #[cfg(target_os="linux")]
    pub unix_apis: crate::platform::linux::fn_defs::UnixApi,
}

impl Codec for ApiTable {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_slice(&self.hashes)?;
        self.seed.encode(enc)?;
        Ok(())
    }
    #[allow(clippy::needless_update)]
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            hashes: dec.read_vec()?,
            seed: dec.read_u32()?,
            ..Default::default()
        })
    }
}

impl ApiTable {
    /// Creates a new ApiTable from a given seed and hash list
    #[allow(clippy::needless_update)]
    pub fn new(seed: u32, hashes: Vec<u32>) -> Self {
        Self {
            hashes,
            seed,
            ..Default::default()
        }

    }
}


/// Small wrapper to store the payload pointer and bytes
pub struct EntryParams {
    /// Pointer to the bytes
    pub ptr: *mut u8,
    /// Size of the payload
    pub len: u64,
}

impl EntryParams {
    /// Reads the bytes from the given pointer
    ///
    /// # Safety
    /// The responsibility of making sure this is safe falls on the caller, to make sure the pointer is valid and the size is correct
    pub unsafe fn to_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len as usize) }
    }
}


/// Settings and parameters used when executing a .NET assembly.
///
/// This structure defines the runtime environment, target domain, class, method,
/// and arguments for .NET payload execution.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct DotnetParameters {
    /// .NET runtime version to use (e.g., `"v4.0.30319"`).
    pub runtime: String,
    /// Application domain name for execution.
    pub domain: String,
    /// Fully qualified class name containing the target method.
    pub class: String,
    /// Name of the method to execute.
    pub method: String,
    /// .NET assembly version string.
    pub version: String,
    /// Arguments passed to the .NET binary.
    pub args: Vec<String>,
}

impl Codec for DotnetParameters {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.runtime.encode(enc)?;
        self.domain.encode(enc)?;
        self.class.encode(enc)?;
        self.method.encode(enc)?;
        self.version.encode(enc)?;
        self.args.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        Ok(Self {
            runtime: String::decode(dec)?,
            domain: String::decode(dec)?,
            class: String::decode(dec)?,
            method: String::decode(dec)?,
            version: String::decode(dec)?,
            args: Vec::<String>::decode(dec)?,
        })
    }
}
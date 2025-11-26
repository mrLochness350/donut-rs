use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::path::PathBuf;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use crate::crypto::crypt::DonutCrypto;
use crate::prelude::{ApiTable, AvBypassOptions, CompressionSettings, DonutValidFileType, DotnetParameters, EntropyLevel, ExitMethod, InstanceType};

/// Represents an embedded module within Donut, including its file data and settings.
///
/// A `DonutModule` holds both the raw and encoded file data, optional encryption and
/// compression settings, and execution parameters for payload delivery.
#[repr(C)]
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct DonutModule {
    /// Original, unmodified file bytes.
    #[cfg_attr(feature = "std", serde(skip))]
    pub file_bytes: Vec<u8>,
    /// Optional cryptographic settings for encrypting the module.
    pub mod_crypto: Option<DonutCrypto>,
    /// Optional compression settings applied to the module.
    pub compression_settings: Option<CompressionSettings>,
    /// Arguments passed to the module when executed.
    pub args: Option<String>,
    /// The detected or specified type of the module (e.g., PE, DLL, .NET).
    pub mod_type: DonutValidFileType,
    /// Parameters specific to .NET assemblies (applies only when `mod_type` is a .NET module).
    pub dotnet_parameters: Option<DotnetParameters>,
    /// Original entry point address of the file.
    pub oep: u32,
    /// CRC32 hash of the original file bytes.
    pub file_crc32: u32,
    /// Original file size (in bytes) for verification purposes.
    pub orig_file_size: u32,
    /// Optional name of the function to invoke after loading the module.
    pub function: Option<String>,
}

#[cfg(feature = "std")]
#[derive(Debug,  Default, Serialize, Deserialize)]
pub(crate) struct InstanceInformation {
    pub(crate) instance: DonutInstance,
    pub(crate) packed_instance: Vec<u8>,
    pub(crate) metadata: InstanceMetadata,
    pub(crate) compressed_instance: Vec<u8>,
}


/// Represents the configuration for an HTTP-based Donut instance.
///
/// This struct defines connection parameters and behavior
/// for retrieving a payload over HTTP or HTTPS.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DonutHttpInstance {
    /// Optional username for basic authentication.
    pub username: Option<String>,
    /// Optional password for basic authentication.
    pub password: Option<String>,
    /// The remote server address (URL or IP).
    pub address: String,
    /// Optional custom endpoint for retrieving the payload.
    pub payload_endpoint: Option<String>,
    /// Number of retry attempts if the request fails.
    pub retry_count: u32,
    /// Optional HTTP request method (e.g., `"GET"`, `"POST"`).
    pub request_method: Option<String>,
    /// Whether to ignore TLS certificate validation errors.
    pub ignore_certs: bool,
}

/// Represents an embedded Donut instance containing a preloaded payload.
///
/// Unlike [`DonutHttpInstance`], this type does not fetch a payload remotely.
/// Instead, it carries the payload directly, along with metadata for validation.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct DonutEmbeddedInstance {
    /// The raw payload bytes embedded in the instance.
    pub payload: Vec<u8>,
    /// The size of the payload in bytes.
    pub payload_size: u32,
    /// A simple hash of the payload for integrity checking.
    pub payload_hash: u32,
}

#[cfg(feature = "std")]
/// Metadata created during the instance build stage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstanceMetadata {
    /// Version number for the API
    pub donut_api_version: u32,
    /// Instance version
    pub version: String,
    /// Instance crc32 value
    pub instance_crc: u32,
    /// Not sure tbh
    pub crc: u32,
    /// Creation timestamp
    pub creation_timestamp: u32,
    /// SHA256 value of the instance (in hex)
    pub sha256: String,
    /// MD5 value of the instance (in hex)
    pub md5: String,
    /// Compressed instance size
    pub compressed_size: u32,
    /// Uncompressed instance size
    pub uncompressed_size: u32,
    /// Is instance encrypted
    pub encrypted: bool,
    /// Local path to the embedded fie
    pub local_file_path: PathBuf,
    /// Seed used for hashing the functions
    pub seed: u32,
    /// Size of the stub
    pub stub_size: u32,
    /// CRC32 value of the stub
    pub stub_crc: u32,
    /// Size of the embedded module
    pub module_size: u32,
    /// CRC32 value of the module
    pub module_crc: u32,
    /// Is the embedded file a .NET executable
    pub is_dotnet: bool,
    /// Instance type
    pub instance_type: InstanceType,
    /// Server address used by the stub in the case of an HTTP instance
    pub stub_server: Option<String>
}


/// Represents a complete Donut execution instance configuration and runtime state.
///
/// This struct holds all metadata, bypass settings, runtime execution parameters,
/// and embedded payload data required for generating and executing a Donut loader instance.
///
/// # Notes
/// - Certain fields are intended only for internal runtime usage and are skipped during serialization.
/// - This structure is marked `#[repr(C)]` to ensure a C-compatible memory layout.
///
/// # Features
/// - When the `std` feature is enabled, the struct supports Serde serialization and deserialization.
#[repr(C)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct DonutInstance {

    /// Optional configuration for AV bypass techniques (e.g., patching AMSI, ETW, etc.).
    pub av_bypass_options: Option<AvBypassOptions>,

    /// Level of entropy/obfuscation applied to the generated loader and payload.
    pub instance_entropy: EntropyLevel,

    /// Method the loader uses to exit after payload execution (e.g., `ExitThread`, `ExitProcess`).
    pub exit_method: ExitMethod,

    /// Optional path to a decoy executable that can be launched to mask loader execution.
    pub decoy_path: Option<String>,

    /// Optional arguments passed to the decoy process if used.
    pub decoy_args: Option<String>,

    /// Internal Donut version number used for compatibility tracking.
    pub version: u32,

    /// Specifies the instance type (e.g., HTTP, embedded, etc.).
    pub instance_type: InstanceType,

    /// HTTP loader configuration (e.g., remote payload URL, retry settings).
    ///
    /// *Not serialized to avoid exposing runtime network configuration when storing instance metadata.*
    #[cfg_attr(feature = "std", serde(skip))]
    pub donut_http_instance: Option<DonutHttpInstance>,

    /// Embedded payload configuration (e.g., in-memory shellcode instance).
    ///
    /// *Not serialized for security reasons and runtime-only relevance.*
    #[cfg_attr(feature = "std", serde(skip))]
    pub donut_embedded_instance: Option<DonutEmbeddedInstance>,

    /// The loaded module representing the actual Donut payload.
    ///
    /// *Not serialized to avoid large binary data in metadata exports.*
    #[cfg_attr(feature = "std", serde(skip))]
    pub donut_module: Option<DonutModule>,

    /// The loader stub configuration and metadata for the runtime shellcode.
    ///
    /// *Not serialized since it is regenerated at runtime.*
    #[cfg_attr(feature = "std", serde(skip))]
    pub stub: Option<DonutInstanceStub>,

    /// Table of dynamically resolved API function pointers required by the loader.
    ///
    /// *Not serialized since it is resolved at runtime during loader execution.*
    #[cfg_attr(feature = "std", serde(skip))]
    pub api_table: ApiTable,

    /// Raw byte buffer of the Donut module or payload appended to the loader stub.
    pub donut_mod_bytes: Vec<u8>,
    #[cfg_attr(feature = "std", serde(skip))]
    /// Donut module length
    pub module_len: u32,
    #[cfg_attr(feature = "std", serde(skip))]
    /// Donut module compression settings
    pub module_compression_settings: CompressionSettings,
    #[cfg_attr(feature = "std", serde(skip))]
    /// Donut module crypto settings
    pub module_crypto: Option<DonutCrypto>,
    #[cfg_attr(feature = "std", serde(skip))]
    /// Donut module Crc32 value
    pub module_crc32: u32
}


/// Represents the loader stub for a Donut instance.
///
/// This structure is loaded before the main instance and is responsible for
/// preparing the embedded instance for execution. It handles decompression,
/// decryption, and integrity verification of the payload before passing
/// control to the actual instance.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub struct DonutInstanceStub {
    /// Version number of the stub format.
    pub version: u32,
    /// Size of the embedded instance data in bytes.
    pub instance_size: u32,
    /// Type of instance being loaded (e.g., HTTP, Embedded).
    pub instance_type: InstanceType,
    /// Raw instance-specific data for the selected `instance_type`.
    pub instance_type_data: Vec<u8>,
    /// Optional encryption settings used to decrypt the embedded instance.
    pub instance_crypt: Option<DonutCrypto>,
    /// CRC32 checksum of the embedded instance for integrity verification.
    pub instance_crc32: u32,
    /// Compression settings for decompressing the embedded instance at load time.
    pub instance_compression_settings: CompressionSettings,
    /// API function table allowing the stub to invoke OS-specific functionality.
    pub api_table: ApiTable,
    /// Check to make sure the payload is or isn't dotnet
    pub is_dotnet: bool,
}
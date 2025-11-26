use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::error::Error;
use core::fmt::Debug;
use azathoth_utils::errors::AzUtilErrorCode;
#[cfg(feature = "std")]
use dataparser_core::DataParseError;

/// Represents all possible errors that can occur while building or executing a Donut instance.
///
/// This enum encapsulates errors from different layers of the Donut pipeline,
/// including module parsing, network communication, compression, cryptographic
/// operations, and runtime loader issues.
///
/// Many variants wrap a descriptive string or another error type for additional context.
///
/// # Example
/// ```
/// use base::errors::{DonutError, DonutResult};
///
/// fn load_module() -> DonutResult<()> {
///     Err(DonutError::InvalidFormat)
/// }
/// ```
#[derive(Debug)]
pub enum DonutError {
    /// An unspecified or unexpected error occurred.
    Unknown {
        /// Inner error string value
        e: String,
    },

    /// A generic error wrapping an arbitrary error type.
    Generic {
        /// Inner error value
        e: Box<dyn Error + Send + Sync + 'static>,
    },

    /// The requested operation or value is not supported.
    Unsupported,

    /// The provided input had an invalid format.
    InvalidFormat,

    /// An invalid engine type was specified.
    InvalidEngine,

    /// An invalid entropy setting was provided.
    InvalidEntropy,

    /// The specified server configuration is invalid.
    InvalidServer,

    /// A required parameter was missing or invalid.
    InvalidParameter,
    /// A required parameter was missing or invalid. Backwards compatible version with arguments
    InvalidParameterStr(String),

    /// The provided header is invalid or malformed.
    InvalidHeader,

    /// A parsing operation failed.
    ParseFailed,

    /// A required object could not be found.
    NotFound(String),

    /// A size mismatch occurred (e.g., payload size does not match expected value).
    SizeMismatch,

    /// A hash mismatch occurred (data integrity check failed).
    HashMismatch,

    /// A header mismatch occurred (e.g., PE or ELF header inconsistency).
    HeaderMismatch,

    /// Version mismatch between components or payloads.
    VersionMismatch,

    /// Failed to resolve an expected API function.
    ApiResolutionFailure,
    /// Failed to resolve an expected API function. Backwards compatible version with arguments
    ApiResolutionFailure2(u32),

    /// A compression-related operation failed.
    CompressionFailure,

    /// An I/O operation failed (includes a string description).
    Io(String),

    /// An error originated from the `goblin` PE/ELF parsing library.
    GoblinError(String),

    /// A module-level error occurred.
    ModuleError,

    /// An instance-level error occurred.
    InstanceError,

    /// A network operation failed.
    NetworkFailure,

    /// A decompression-related operation failed.
    DecompressionFailure,

    /// A data parsing error occurred (only available with `std` feature).
    #[cfg(feature = "std")]
    DataParseError(String),

    /// A serialization or deserialization error occurred (only available with `std` feature).
    #[cfg(feature = "std")]
    SerializationError(String),

    /// Unexpected end-of-file while reading input data.
    UnexpectedEof,

    /// The provided function signature is unsupported.
    UnsupportedSignature(String),

    /// A .NET-related error occurred (execution or parsing failure).
    DotnetError,

    /// A build-related error occurred.
    BuildError(String),

    /// Memory alignment is incorrect or invalid for the operation.
    BadAlignment,

    /// Memory allocation failed.
    AllocFailed,

    /// Other, unspecified error
    Other(String),

    /// Azathoth errors
    Azathoth(String),

    /// Cryptography-specific errors
    CryptoError,
}
impl DonutError {
    /// Converts the error enum to its u32 representation
    pub fn as_u32(&self) -> u32 {
        match self {
            DonutError::Unknown { .. } => 88,
            DonutError::Generic { .. } => 89,
            DonutError::Other(_) => 90,
            DonutError::Unsupported => 91,
            DonutError::InvalidFormat => 1,
            DonutError::InvalidEngine => 2,
            DonutError::InvalidEntropy => 3,
            DonutError::InvalidServer => 4,
            DonutError::InvalidParameter => 5,
            DonutError::InvalidParameterStr(_) => 6,
            DonutError::InvalidHeader => 7,
            DonutError::ParseFailed => 8,
            DonutError::NotFound(_) => 9,
            DonutError::SizeMismatch => 10,
            DonutError::HashMismatch => 11,
            DonutError::HeaderMismatch => 12,
            DonutError::VersionMismatch => 13,
            DonutError::ApiResolutionFailure => 14,
            DonutError::CompressionFailure => 15,
            DonutError::Io(_) => 16,
            DonutError::GoblinError(_) => 17,
            DonutError::ModuleError => 18,
            DonutError::InstanceError => 19,
            DonutError::NetworkFailure => 20,
            DonutError::DecompressionFailure => 21,
            DonutError::BadAlignment => 22,
            DonutError::AllocFailed => 23,
            DonutError::Azathoth(_) => 27,
            DonutError::CryptoError => 28,
            #[cfg(feature = "std")]
            DonutError::DataParseError(_) => 29,
            DonutError::UnexpectedEof => 30,
            DonutError::UnsupportedSignature(_) => 31,
            DonutError::DotnetError => 32,
            DonutError::BuildError(_) => 33,
            #[cfg(feature = "std")]
            DonutError::SerializationError(_) => 34,
            DonutError::ApiResolutionFailure2(e) => pack16(35, *e as u16)

        }
    }
    /// Converts the error enum to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            DonutError::Unknown { .. } => "Unknown Error",
            DonutError::Generic { .. } => "Generic Error",
            DonutError::Other(_) => "Other Error",
            DonutError::Unsupported => "Unsupported Value",
            DonutError::ParseFailed => "Failed to parse",
            DonutError::InvalidFormat => "Invalid format",
            DonutError::InvalidParameter => "Invalid parameter",
            DonutError::InvalidEngine => "Invalid engine",
            DonutError::InvalidEntropy => "Invalid entropy",
            DonutError::InvalidServer => "Invalid server",
            DonutError::NotFound(_) => "File not found",
            DonutError::SizeMismatch => "Size mismatch",
            DonutError::HashMismatch => "Hash mismatch",
            DonutError::HeaderMismatch => "Header mismatch",
            DonutError::VersionMismatch => "Version mismatch",
            DonutError::ApiResolutionFailure => "API resolution failure",
            DonutError::CompressionFailure => "Compression failure",
            DonutError::Io(_) => "IO error",
            DonutError::GoblinError(_) => "Goblin error",
            DonutError::ModuleError => "Module error",
            DonutError::InstanceError => "Instance error",
            DonutError::NetworkFailure => "Network failure",
            DonutError::DecompressionFailure => "Decompression failure",
            #[cfg(feature = "std")]
            DonutError::DataParseError(_) => "Data parse error",
            DonutError::UnexpectedEof => "Unexpected EOF",
            DonutError::UnsupportedSignature(_) => "Unsupported function signature",
            DonutError::DotnetError => "Dotnet error",
            DonutError::BuildError(_) => "Build error",
            DonutError::InvalidHeader => "Invalid header",
            DonutError::BadAlignment => "Bad alignment",
            DonutError::AllocFailed => "Alloc Failed",
            DonutError::Azathoth(_) => "Azathoth Error" ,
            #[cfg(feature = "std")]
            DonutError::SerializationError(_) => "Serialization error",
            DonutError::CryptoError => "Crypto Error" ,
            DonutError::InvalidParameterStr(_) => "Invalid parameter",
            DonutError::ApiResolutionFailure2(_) => "API resolution failure (2)",
        }
    }
}



/// Wrapper around `Result<T,E>` for simplicity
pub type DonutResult<T> = Result<T, DonutError>;

#[cfg(feature = "std")]
impl core::fmt::Display for DonutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DonutError::Unknown { e } => write!(f, "Unknown Error: {e}"),
            DonutError::Generic { e } => write!(f, "Generic Error: {e}"),
            DonutError::Other(e) => write!(f, "Other Error: {e}"),
            DonutError::Unsupported => write!(f, "Unsupported Value!"),
            DonutError::ParseFailed => write!(f, "Failed to parse!"),
            DonutError::InvalidFormat => write!(f, "Invalid format!"),
            DonutError::InvalidParameter => write!(f, "Invalid parameter!"),
            DonutError::InvalidEngine => write!(f, "Invalid engine!"),
            DonutError::InvalidEntropy => write!(f, "Invalid entropy!"),
            DonutError::InvalidServer => write!(f, "Invalid server!"),
            DonutError::NotFound(e) => write!(f, "Object not found: {e}"),
            DonutError::SizeMismatch => write!(f, "Size Mismatch!"),
            DonutError::HashMismatch => write!(f, "Hash Mismatch!"),
            DonutError::HeaderMismatch => write!(f, "Header Mismatch!"),
            DonutError::VersionMismatch => write!(f, "Version Mismatch!"),
            DonutError::ApiResolutionFailure => write!(f, "Api Resolution Failure!"),
            DonutError::CompressionFailure => write!(f, "Compression Failure!"),
            DonutError::Io(e) => write!(f, "Io Error: {e}"),
            DonutError::GoblinError(e) => write!(f, "Goblin Error: {e}"),
            DonutError::ModuleError => write!(f, "Module Error"),
            DonutError::InstanceError => write!(f, "Instance Error"),
            DonutError::NetworkFailure => write!(f, "Network Failure"),
            DonutError::DecompressionFailure => write!(f, "Decompression Failure"),
            DonutError::DataParseError(e) => write!(f, "Data Parse Error: {e}"),
            DonutError::UnexpectedEof => write!(f, "Unexpected EOF"),
            DonutError::UnsupportedSignature(e) => write!(f, "Unsupported function signature: {e}"),
            DonutError::DotnetError => write!(f, "Dotnet Error"),
            DonutError::BuildError(e) => write!(f, "Build Error: {e}"),
            DonutError::InvalidHeader => write!(f, "Invalid header"),
            DonutError::BadAlignment => write!(f, "Bad alignment"),
            DonutError::AllocFailed => write!(f, "Alloc Failed"),
            DonutError::SerializationError(e) => write!(f, "Serialization Error: {e}"),
            DonutError::Azathoth(e) => write!(f, "Azathoth Error: {e}"),
            DonutError::CryptoError => write!(f, "Crypto Error"),
            DonutError::InvalidParameterStr(e) => write!(f, "Invalid parameter: {e}"),
            DonutError::ApiResolutionFailure2(e) => write!(f, "Api Resolution Failure: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for DonutError {}
#[cfg(feature = "std")]
impl From<std::io::Error> for DonutError {
    fn from(e: std::io::Error) -> Self {
        DonutError::Io(e.to_string())
    }
}


#[cfg(feature = "std")]
impl From<DonutError> for std::io::Error {
    fn from(e: DonutError) -> Self {
        std::io::Error::other(e)
    }
}

#[cfg(feature = "std")]
impl From<serde::de::value::Error> for DonutError {
    fn from(e: serde::de::value::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}
#[cfg(feature = "std")]
impl From<goblin::error::Error> for DonutError {
    fn from(e: goblin::error::Error) -> Self {
        DonutError::GoblinError(e.to_string())
    }
}
#[cfg(feature = "std")]
impl From<DataParseError> for DonutError {
    fn from(value: DataParseError) -> Self {
        Self::DataParseError(value.to_string())
    }
}


impl From<AzUtilErrorCode> for DonutError {
    fn from(value: AzUtilErrorCode) -> Self {
        Self::Azathoth(value.to_string())
    }
}

#[inline(always)]
const fn pack16(hi: u16, lo: u16) -> u32 {
    ((hi as u32) << 16) | lo as u32
}
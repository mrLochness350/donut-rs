use alloc::string::{String, ToString};
use core::str::FromStr;
use azathoth_utils::codec::{Codec, Decoder, Encoder};
use azathoth_utils::errors::{AzUtilErrorCode, AzUtilResult};
use azathoth_utils::formatter::{FDisplay, FormatSpec, WriteBuffer};
use crate::errors::DonutError;

/// Specifies the level of entropy or obfuscation applied to the payload.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum EntropyLevel {
    /// No additional entropy or obfuscation (default).
    #[default]
    None = 0,
    /// High entropy, strong obfuscation (more randomization).
    High = 1,
    /// Light entropy, minimal obfuscation.
    Light = 2,
    /// Average entropy, balanced obfuscation.
    Average = 3,
}

impl Codec for EntropyLevel {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        match b {
            0 => Ok(EntropyLevel::None),
            1 => Ok(EntropyLevel::High),
            2 => Ok(EntropyLevel::Light),
            3 => Ok(EntropyLevel::Average),
            _ => Err(AzUtilErrorCode::CodecError)
        }
    }
}

impl FromStr for EntropyLevel {
    type Err = DonutError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "heavy" => Ok(Self::High),
            "light" => Ok(Self::Light),
            "average" => Ok(Self::Average),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}


/// Represents valid file types for processing.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum DonutValidFileType {
    /// Dynamic-link library (optional .NET).
    Dll {
        /// Is a .NET DLL
        dotnet: bool
    },
    /// Windows PE executable (optional .NET).
    PE {
        /// Is a .NET PE file
        dotnet: bool
    },
    /// Script file with a specified script type.
    Script {
        /// Script type
        script_type: DonutValidScriptType
    },
    /// Linux shared object.
    SharedObject,
    /// ELF binary format.
    ELF,
    /// Unknown or unsupported type.
    #[default]
    Unknown
}

#[cfg(feature = "std")]
impl std::fmt::Display for DonutValidFileType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DonutValidFileType::Dll { dotnet } => { write!(fmt, "DLL -> Dotnet: {dotnet}") }
            DonutValidFileType::PE {dotnet} =>  { write!(fmt, "PE -> Dotnet: {dotnet}") }
            DonutValidFileType::ELF => { write!(fmt, "ELF") }
            DonutValidFileType::SharedObject => { write!(fmt, "SharedObject -> ELF") }
            DonutValidFileType::Script {..} => { write!(fmt, "Script") }
            _ => write!(fmt, "Unknown DonutValidFileType")
        }
    }
}

impl Codec for DonutValidFileType {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        match self {
            Self::Dll { dotnet } => {
                enc.push_u8(0)?;
                enc.push_u8(*dotnet as u8)
            }
            Self::PE { dotnet } => {
                enc.push_u8(1)?;
                enc.push_u8(*dotnet as u8)
            }
            Self::Script { script_type } => {
                enc.push_u8(2)?;
                script_type.encode(enc)
            }
            Self::SharedObject => enc.push_u8(3),
            Self::ELF => enc.push_u8(4),
            Self::Unknown => enc.push_u8(5),
        }
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        match dec.read_u8()? {
            0 => Ok(Self::Dll { dotnet: dec.read_u8()? != 0 }),
            1 => Ok(Self::PE { dotnet: dec.read_u8()? != 0 }),
            2 => {
                let s = DonutValidScriptType::decode(dec).map_err(|_| AzUtilErrorCode::CodecError)?;
                Ok(Self::Script { script_type: s })
            }
            3 => Ok(Self::SharedObject),
            4 => Ok(Self::ELF),
            5 => Ok(Self::Unknown),
            _ => Err(AzUtilErrorCode::CodecError),
        }
    }
}


/// Supported script file types.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum DonutValidScriptType {
    /// JScript file.
    JScript,
    /// Python script.
    Python,
    /// VBScript file.
    VBScript,
    /// Windows Script Host script (default).
    #[default]
    WScript,
    /// Lua script file.
    Lua,
}

impl Codec for DonutValidScriptType {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        let val = match self {
            Self::JScript => 0,
            Self::Python => 1,
            Self::VBScript => 2,
            Self::WScript => 3,
            Self::Lua => 4,
        };
        enc.push_u8(val)
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        match dec.read_u8()? {
            0 => Ok(Self::JScript),
            1 => Ok(Self::Python),
            2 => Ok(Self::VBScript),
            3 => Ok(Self::WScript),
            4 => Ok(Self::Lua),
            _ => Err(AzUtilErrorCode::CodecError),
        }
    }
}

/// Output formats for generated payloads or code.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum OutputFormat {
    /// Ruby byte array format output
    Ruby,
    /// C byte array format output
    C,
    /// C# byte array format output
    CSharp,
    /// Powershell byte array format output
    Powershell,
    /// Rust byte array format output
    Rust,
    /// Python  byte array format output
    Python,
    /// Raw binary output (default).
    #[default]
    Raw,
    /// Hex output
    Hex,
    /// UUID Output
    Uuid,
    /// Base64 encoded string output
    Base64,
    /// Golang byte array output
    Golang
}

impl Codec for OutputFormat {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        let val = match self {
            Self::Ruby => 0,
            Self::C => 1,
            Self::CSharp => 2,
            Self::Powershell => 3,
            Self::Rust => 4,
            Self::Python => 5,
            Self::Raw => 6,
            Self::Hex => 7,
            Self::Uuid => 8,
            Self::Base64 => 9,
            Self::Golang => 10,
        };
        enc.push_u8(val)
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        match dec.read_u8()? {
            0 => Ok(Self::Ruby),
            1 => Ok(Self::C),
            2 => Ok(Self::CSharp),
            3 => Ok(Self::Powershell),
            4 => Ok(Self::Rust),
            5 => Ok(Self::Python),
            6 => Ok(Self::Raw),
            7 => Ok(Self::Hex),
            8 => Ok(Self::Uuid),
            9 => Ok(Self::Base64),
            10 => Ok(Self::Golang),
            _ => Err(AzUtilErrorCode::CodecError),
        }
    }
}


impl From<&String> for OutputFormat {
    fn from(value: &String) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "ruby" | "rb" => Self::Ruby,
            "c" => Self::C,
            "csharp" | "cs" => Self::CSharp,
            "powershell" | "ps1" => Self::Powershell,
            "rust" | "rs" => Self::Rust,
            "python" | "py" => Self::Python,
            "hex" => Self::Hex,
            "uuid" => Self::Uuid,
            "base64" => Self::Base64,
            "golang" | "go" => Self::Golang,
            _ => Self::Raw
        }
    }
}

impl OutputFormat {
    /// Returns the default file extension associated with each output format.
    ///
    /// # Examples
    /// ```
    /// use base::types::enums::OutputFormat;
    /// assert_eq!(OutputFormat::Python.extension(), "py");
    /// ```
    pub fn extension(self) -> &'static str {
        match self {
            OutputFormat::Ruby => "rb",
            OutputFormat::C => "c",
            OutputFormat::CSharp => "cs",
            OutputFormat::Powershell => "ps1",
            OutputFormat::Rust => "rs",
            OutputFormat::Python => "py",
            OutputFormat::Raw => "bin",
            OutputFormat::Hex => "hex",
            OutputFormat::Uuid => "uuid",
            OutputFormat::Base64 => "b64",
            OutputFormat::Golang => "go"
        }
    }
}

/// Defines how the injected code should terminate after execution.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum ExitMethod {
    /// Exit the thread (default).
    #[default]
    ExitThread = 0,
    /// Exit the entire process.
    ExitProcess = 1,
    /// Do not exit automatically.
    NeverExit = 2
}


impl From<u8> for ExitMethod {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::ExitThread,
            1 => Self::ExitProcess,
            2 => Self::NeverExit,
            _ => Self::ExitProcess
        }
    }
}

impl From<ExitMethod> for u8 {
    fn from(value: ExitMethod) -> Self {
        match value {
            ExitMethod::ExitThread => 0,
            ExitMethod::ExitProcess => 1,
            ExitMethod::NeverExit => 2,
        }
    }
}

impl Codec for ExitMethod {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        let b = dec.read_u8()?;
        Ok(b.into())
    }
}


impl FromStr for ExitMethod {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "exitthread" => Ok(ExitMethod::ExitThread),
            "exitprocess" => Ok(ExitMethod::ExitProcess),
            "exitblock" => Ok(ExitMethod::NeverExit),
            _ => Err("must be 'ExitThread', 'ExitProcess' or 'ExitBlock'"),
        }
    }
}


/// Specifies the type of payload instance.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum InstanceType {
    /// HTTP-based instance (default).
    #[default]
    Http = 0,
    /// Embedded (local) instance.
    Embedded = 1,
}

#[cfg(feature="std")]
impl std::fmt::Display for InstanceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            InstanceType::Http => "http",
            InstanceType::Embedded => "embedded",
        }.to_string();
        write!(f, "{str}")
    }
}

impl Codec for InstanceType {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        match b {
            0 => Ok(Self::Http),
            1 => Ok(Self::Embedded),
            _ => Err(AzUtilErrorCode::CodecError)
        }
    }
}

impl FromStr for InstanceType {
    type Err = DonutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "embedded" => Ok(Self::Embedded),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}


impl FromStr for AmsiBypassTechnique {
    type Err = DonutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "patch_scan_buffer" => Ok(Self::PatchAmsiScanBuffer),
            "patch_dll_export" => Ok(Self::PatchAmsiDllExport),
            "patch_dispatch_table" => Ok(Self::PatchAmsiDispatchTable),
            "none" => Ok(Self::None),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}

/// Techniques to bypass AMSI (Antimalware Scan Interface).
#[repr(u8)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum AmsiBypassTechnique {
    /// No AMSI bypass (default).
    #[default]
    None = 0,
    /// Patch AmsiScanBuffer.
    PatchAmsiScanBuffer = 1,
    /// Patch AMSI DLL exports.
    PatchAmsiDllExport = 2,
    /// Patch the AMSI dispatch table.
    PatchAmsiDispatchTable = 3,
}
impl Codec for AmsiBypassTechnique {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        match b {
            0 => Ok(Self::None),
            1 => Ok(Self::PatchAmsiScanBuffer),
            2 => Ok(Self::PatchAmsiDllExport),
            3 => Ok(Self::PatchAmsiDispatchTable),
            _ => Err(AzUtilErrorCode::CodecError)
        }
    }
}

/// Techniques to bypass ETW (Event Tracing for Windows).
#[repr(u8)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum EtwBypassTechnique {
    /// No ETW bypass (default).
    #[default]
    None = 0,
    /// Patch EtwEventWrite function.
    PatchEtwEventWrite = 1,
    /// Disable ETW tracing.
    EtwDisableTracing = 2
}

impl Codec for EtwBypassTechnique {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        match b {
            0 => Ok(Self::None),
            1 => Ok(Self::PatchEtwEventWrite),
            2 => Ok(Self::EtwDisableTracing),
            _ => Err(AzUtilErrorCode::CodecError)
        }
    }
}


/// Supported architectures.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum Arch {
    /// 32-bit x86 architecture.
    X86 = 0,
    #[default]
    /// 64-bit x86 architecture (default).
    X86_64 = 1,
    /// Alias for 64-bit architecture.
    X64 = 2
}

impl Codec for Arch {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        match b {
            0 => Ok(Self::X86),
            1 => Ok(Self::X86_64),
            2 => Ok(Self::X64),
            _ => Err(AzUtilErrorCode::CodecError)
        }
    }
}


impl FromStr for Arch {
    type Err = DonutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "x86" => Ok(Self::X86),
            "x64" | "x86_64" => Ok(Self::X64),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}


/// Encryption provider
#[repr(u8)]
#[derive(PartialEq, Clone, PartialOrd, Copy, Debug, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum DonutCryptoProvider {
    /// No encryption
    #[default]
    None = 0,
    /// XOR encoding provider
    Xor = 1,
    /// Aes encryption provider
    Aes = 2,
}

impl FDisplay for DonutCryptoProvider {
    fn fmt<W: WriteBuffer>(&self, w: &mut W, _spec: &FormatSpec) -> AzUtilResult<()> {
        let str = match self {
            DonutCryptoProvider::None => "none",
            DonutCryptoProvider::Xor => "xor",
            DonutCryptoProvider::Aes => "aes",
        };

        w.write_str(str)
    }
}

impl From<DonutCryptoProvider> for u8 {
    fn from(value: DonutCryptoProvider) -> Self {
        match value {
            DonutCryptoProvider::None => 0,
            DonutCryptoProvider::Xor => 1,
            DonutCryptoProvider::Aes => 2,
        }
    }
}

impl From<u8> for DonutCryptoProvider {
    fn from(v: u8) -> Self {
        match v {
            2 => Self::Aes,
            1 => Self::Xor,
            _ => Self::None
        }
    }
}

impl Codec for DonutCryptoProvider {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(*self as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        match b {
            2 => Ok(Self::Aes),
            1 => Ok(Self::Xor),
            0 => Ok(Self::None),
            _ => Err(AzUtilErrorCode::CodecError)
        }
    }
}

impl FromStr for DonutCryptoProvider {
    type Err = DonutError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "aes" => Ok(Self::Aes),
            "xor" => Ok(Self::Xor),
            "none" => Ok(Self::None),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}


#[cfg(feature = "std")]
impl std::fmt::Display for DonutCryptoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Xor => write!(f, "xor"),
            Self::Aes => write!(f, "aes"),
        }
    }
}
use alloc::string::ToString;
use core::str::FromStr;
use azathoth_utils::codec::{Codec, Decoder, Encoder};
use azathoth_utils::errors::AzUtilResult;
use azathoth_utils::formatter::{FDisplay, FormatSpec, WriteBuffer};
use crate::errors::DonutError;

/// Defines supported compression engines for payloads or data streams.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum CompressionEngine {
    /// No compression applied.
    #[default]
    None,
    /// Gzip compression.
    Gzip,
    /// Zlib compression format.
    Zlib,
    /// XPRESS (fast LZ-based) compression.
    Xpress,
    /// LZNT1 compression used in Windows.
    Lznt1,
}

#[cfg(not(feature="std"))]
impl core::fmt::Display for CompressionEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let str = match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Xpress => "xpress",
            Self::Lznt1 => "lznt1",
        }
            .to_string();
        write!(f, "{str}")
    }
}

impl FDisplay for CompressionEngine {
    fn fmt<W: WriteBuffer>(&self, w: &mut W, _spec: &FormatSpec) -> AzUtilResult<()> {
        let str = match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Xpress => "xpress",
            Self::Lznt1 => "lznt1",
        };
        w.write_str(str)
    }
}

#[cfg(feature="std")]
impl std::fmt::Display for CompressionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Xpress => "xpress",
            Self::Lznt1 => "lznt1",
        }
            .to_string();
        write!(f, "{str}")
    }
}

impl Codec for CompressionEngine {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        Ok(b.into())
    }
}

impl From<CompressionEngine> for u8 {
    fn from(value: CompressionEngine) -> Self {
        match value {
            CompressionEngine::None => 0,
            CompressionEngine::Gzip => 1,
            CompressionEngine::Zlib => 2,
            CompressionEngine::Xpress => 3,
            CompressionEngine::Lznt1 => 4,
        }
    }
}

impl From<u8> for CompressionEngine {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Gzip,
            2 => Self::Zlib,
            3 => Self::Xpress,
            4 => Self::Lznt1,
            _ => Self::None,
        }
    }
}
impl FromStr for CompressionEngine {
    type Err = DonutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            "xpress" => Ok(Self::Xpress),
            "lzn1" => Ok(Self::Lznt1),
            "zlib" => Ok(Self::Zlib),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}

/// Specifies the strength or ratio of compression to apply.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialOrd, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "PascalCase"))]
pub enum CompressionLevel {
    /// No compression (default).
    #[default]
    None,
    /// Balanced compression
    Normal,
    /// Maximum compression ratio.
    Maximum
}

#[cfg(feature="std")]
impl std::fmt::Display for CompressionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            CompressionLevel::None => "none".to_string(),
            CompressionLevel::Normal => "normal".to_string(),
            CompressionLevel::Maximum => "maximum".to_string()
        };
        write!(f, "{str}")
    }
}

#[cfg(not(feature="std"))]
impl core::fmt::Display for CompressionLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let str = match self {
            CompressionLevel::None => "none".to_string(),
            CompressionLevel::Normal => "normal".to_string(),
            CompressionLevel::Maximum => "maximum".to_string()
        };
        write!(f, "{str}")
    }
}

impl FDisplay for CompressionLevel {
    fn fmt<W: WriteBuffer>(&self, w: &mut W, _spec: &FormatSpec) -> AzUtilResult<()> {
        let str = match self {
            CompressionLevel::None => "none"      ,
            CompressionLevel::Normal => "normal"  ,
            CompressionLevel::Maximum => "maximum"
        };
        w.write_str(str)
    }
}

impl Codec for CompressionLevel {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u8(self.clone() as u8)
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self> {
        let b = dec.read_u8()?;
        Ok(b.into())
    }
}

impl From<CompressionLevel> for u8 {
    fn from(value: CompressionLevel) -> Self {
        match value {
            CompressionLevel::Normal => 0,
            CompressionLevel::Maximum => 1,
            CompressionLevel::None => 2
        }
    }
}

impl From<u8> for CompressionLevel {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Normal,
            2 => Self::Maximum,
            _ => Self::Normal
        }
    }
}


impl FromStr for CompressionLevel {
    type Err = DonutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "normal" => Ok(Self::Normal),
            "maximum" => Ok(Self::Maximum),
            _ => Err(DonutError::Unknown {e: s.to_string()}),
        }
    }
}
use core::ffi::CStr;
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::format;
use crate::errors::{DonutError, DonutResult};
#[cfg(feature = "std")]
use std::fs::{File, OpenOptions};
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};
use azathoth_utils::codec::{Codec, Decoder, Encoder};
#[cfg(feature = "std")]
use dataparser_core::{DataParser, Endianness, ParseOptions};
#[cfg(feature = "std")]
use goblin::pe::PE;
#[cfg(feature = "std")]
use hex::FromHex;
#[cfg(feature = "std")]
use rand::distr::Alphanumeric;
#[cfg(feature = "std")]
use rand::{Rng, RngCore};
#[cfg(feature = "std")]
use serde::de::Error;
#[cfg(feature = "std")]
use serde::Deserialize;
#[cfg(feature = "std")]
use crate::fs::pe::rva_to_offset;
#[cfg(feature = "std")]
use crate::types::enums::OutputFormat;

#[inline(always)]
#[unsafe(link_section = ".text")]
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
        "rdtsc",
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[unsafe(link_section = ".text")]
pub(crate) fn gen_rand_byte_array(len: usize) -> Vec<u8> {
    let mut seed = rdtsc();
    let mut buf = alloc::vec![0u8; len];

    for byte in &mut buf {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (seed >> 32) as u8;
    }

    buf
}


/// Computes a hash for a function name with a seed value.
///
/// Converts the string to uppercase and computes a 32-bit hash using
/// a rotate-add-xor algorithm.
///
/// # Returns
/// A 32-bit hash of the function name.
#[unsafe(link_section = ".text")]
pub fn donut_hasher(func: &str, seed: u32) -> u32 {
    let mut hash = seed;
    let func = func.to_ascii_uppercase();
    for b in func.bytes() {
        let b = b.to_ascii_uppercase();
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(b as u32);
        hash ^= hash >> 7;
    }
    hash
}

/// Converts a raw C string pointer to a Rust string slice.
///
/// # Safety
/// The caller must ensure that the pointer is valid and points to
/// a null-terminated UTF-8 string.
#[inline(always)]
#[unsafe(link_section = ".text")]
pub fn ptr_to_str(ptr: *const u8) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }

    unsafe {
        CStr::from_ptr(ptr as *const i8)
            .to_str()
            .ok()
    }
}

/// Converts a Rust UTF-8 string to a wide-character pointer (UTF-16).
#[inline(always)]
#[unsafe(link_section = ".text")]
pub fn str_to_wide_ptr(s: &str) -> *mut u16 {
    let mut wide: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
    let ptr = wide.as_mut_ptr();
    core::mem::forget(wide);
    ptr
}

/// Converts a wide-character pointer to a Rust UTF-8 `String`.
///
/// # Safety
/// The pointer must be valid and point to a null-terminated UTF-16 string.
#[unsafe(link_section = ".text")]
pub unsafe fn from_wide_ptr(ptr: *const u16) -> Option<String> {
    unsafe {
        if ptr.is_null() {
            return None;
        }
        let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
        let slice = core::slice::from_raw_parts(ptr, len);
        String::from_utf16(slice).ok()
    }
}

/// Converts a byte slice to its lowercase hexadecimal string representation.
#[unsafe(link_section = ".text")]
pub fn to_hex<D: Into<Vec<u8>>>(data: D) -> String {
    const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";
    let input: Vec<u8> = data.into();
    let mut buf = Vec::with_capacity(input.len() * 2);

    for byte in input {
        buf.push(HEX_TABLE[(byte >> 4) as usize]);
        buf.push(HEX_TABLE[(byte & 0x0F) as usize]);
    }

    String::from_utf8(buf).unwrap()
}

/// Decodes a hexadecimal string into a byte vector.
#[unsafe(link_section = ".text")]
pub fn from_hex(data: &str) -> DonutResult<Vec<u8>> {
    assert_eq!(data.len() % 2, 0, "Hex string must be even-length");

    fn hex_char_to_val(c: u8) -> DonutResult<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DonutError::Other(format!("Invalid hex character: {}", c as char)))
        }
    }
    let bytes = data.as_bytes();
    let mut out = Vec::with_capacity(data.len() / 2);

    for i in (0..data.len()).step_by(2) {
        let high = hex_char_to_val(bytes[i])? << 4;
        let low = hex_char_to_val(bytes[i + 1])?;
        out.push(high | low);
    }
    Ok(out)
}

/// Converts a `Vec<T>` into a `VecDeque<T>`.
#[unsafe(link_section = ".text")]
pub fn vec_to_vecdeque<T>(vec: Vec<T>) -> alloc::collections::VecDeque<T> {
    alloc::collections::VecDeque::from(vec)
}

/// Converts a Rust string into a null-terminated C-style string as `Vec<u8>`.
#[unsafe(link_section = ".text")]
pub fn to_cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    if !v.ends_with(&[0]) {
        v.push(0);
    }
    v
}

/// Pops exactly `N` bytes from the front of a `VecDeque<u8>`.
#[unsafe(link_section = ".text")]
pub fn pop_exact<const N: usize>(deque: &mut alloc::collections::VecDeque<u8>) -> DonutResult<[u8; N]> {
    let mut buf = [0u8; N];
    for b in buf.iter_mut() {
        *b = deque.pop_front().ok_or(DonutError::ParseFailed)?;
    }
    Ok(buf)
}

/// Pops exactly `N` bytes from a `Vec<u8>` (LIFO order).
#[unsafe(link_section = ".text")]
pub fn pop_exact_vec<const N: usize>(v: &mut Vec<u8>) -> DonutResult<[u8; N]> {
    let mut buf = [0u8; N];
    for b in buf.iter_mut() {
        *b = v.pop().ok_or(DonutError::ParseFailed)?;
    }
    Ok(buf)
}



#[cfg(feature = "std")]
pub(crate) fn generate_windows_hashes(seed: u32) -> Vec<u32> {
    let mut hashes = Vec::new();
    for entry in crate::platform::windows::consts::WINDOWS_UTILITIES {
        hashes.push(donut_hasher(entry, seed));
    }
    hashes
}

#[cfg(all(feature = "std", feature="unstable"))]
pub(crate) fn generate_unix_hashes(seed: u32) -> Vec<u32> {
    let mut hashes = Vec::new();
    for entry in crate::platform::linux::consts::LINUX_UTILITIES {
        hashes.push(donut_hasher(entry, seed));
    }
    hashes
}

#[cfg(all(feature = "std", not(feature="unstable")))]
pub(crate) fn generate_unix_hashes(_seed: u32) -> Vec<u32> {
    unimplemented!("unix hashes are still unstable. it is not recommended to use them")
}

#[cfg(feature = "std")]
pub(crate) fn build_http_url(base: &str, endpoint: &Path) -> String {
    let endpoint = endpoint.to_string_lossy().to_string();
    let base = base.trim_end_matches('/');
    let endpoint = endpoint.trim_start_matches('/');
    format!("{base}/{endpoint}")
}



#[cfg(feature = "std")]
pub(crate) fn extract_dotnet_runtime_version(pe: &PE, data: &mut [u8]) -> DonutResult<String> {
    let clr_rva = match pe.header.optional_header.ok_or(DonutError::ParseFailed)?.data_directories.get_clr_runtime_header()
    {
        Some(clr) => clr,
        None => return Err(DonutError::InvalidFormat)
    }.virtual_address as u64;

    let clr_offset = rva_to_offset(pe, clr_rva as u32)?;
    let mut opts = ParseOptions::default();
    opts.set_endianness(Endianness::LittleEndian);
    let mut dp = DataParser::with_options(&mut data[clr_offset as usize..], opts.clone());
    let _cb = dp.get_u32().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let _major = dp.get_u16().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let _minor = dp.get_u16().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let metadata_rva=  dp.get_u32().map_err(|e| DonutError::Unknown {e: e.to_string()})? as u64;
    let _metadata_size = dp.get_u32().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let metadata_offset = rva_to_offset(pe, metadata_rva as u32)?;
    let mut mdp = DataParser::with_options(&mut data[metadata_offset as usize..], opts);
    let _sig = mdp.get_u32().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let _major_v = mdp.get_u16().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let _minor_v = mdp.get_u16().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let _reserved = mdp.get_u32().map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let version_len = mdp.get_u32().map_err(|e| DonutError::Unknown {e: e.to_string()})? as usize;
    let version_buf = mdp.get_bytes(version_len).map_err(|e| DonutError::Unknown {e: e.to_string()})?;
    let version_str = String::from_utf8_lossy(&version_buf)
        .trim_end_matches('\0')
        .to_string();

    Ok(version_str)
}

#[cfg(feature = "std")]
/// Opens a given path for writing **MAY BE REMOVED IN THE FUTURE**
pub fn write_to_file(path: Option<PathBuf>) -> DonutResult<File> {
    let output = if let Some(name) = &path {
        name.clone()
    } else {
        format!(
            "{}.bin",
            gen_rand_string(5).to_ascii_uppercase()
        )
            .into()
    };
    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&output)
        .map_err(|e| DonutError::Io(format!("Failed to open output file for writing: {} -> {}", output.display(), e)))?;
    Ok(file)
}


#[cfg(feature = "std")]
/// Creates or truncates a file and opens it for writing
pub fn create_file(pb: &String) -> DonutResult<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(pb).map_err(|e| DonutError::Io(e.to_string()))
}
#[cfg(feature = "std")]
pub(crate) fn de_hex2vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    Vec::from_hex(s).map_err(|e| Error::custom(format!("invalid hex: {}", e)))
}

#[cfg(feature = "std")]
pub(crate) fn gen_rand_string(len: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}


#[cfg(feature = "std")]
pub(crate) fn bytes_to_str(b: &[u8]) -> String {
    let nul_pos = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..nul_pos]).to_string()
}

#[cfg(feature = "std")]
pub(crate) fn default_file_name(filename: &str, extension: OutputFormat) -> String {
    let random = gen_rand_string(5);
    let path = Path::new(filename);

    let base_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    format!("{}_{}.{}", base_name, random, extension.extension())
}


#[cfg(feature = "std")]
/// Generates a random u32 seed
pub fn gen_seed() -> u32 {
    rand::rng().next_u32()
}

/// Helper to simplify encoding operations
pub trait ToBytes: Codec {
    /// Converts a given item to bytes
    fn to_bytes(&self) -> DonutResult<Vec<u8>> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder)?;
        Ok(encoder.into_inner())
    }
}
impl <T: Codec> ToBytes for T {}

/// Helper to simplify decoding operations
pub trait FromBytes<T: Codec> {
    /// Converts a byte array to a type `T` that implements [`Codec`]
    fn from_bytes(bytes: &[u8]) -> DonutResult<T> {
        let mut decoder = Decoder::new(bytes);
        T::decode(&mut decoder).map_err(|e| DonutError::Azathoth(e.to_string()))
    }
}

impl <T: Codec> FromBytes<T> for T {}
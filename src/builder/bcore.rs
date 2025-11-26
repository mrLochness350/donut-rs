use crate::builder::utils::{extract_info, patch_marker};
use crate::errors::DonutResult;
#[cfg(feature="unstable")]
use crate::platform::linux::loader_unix::LOADER_UNIX;
use crate::platform::windows::consts::{LOADER_ENTRY_OFFSET_MARKER, PAYLOAD_LEN_MARKER, PAYLOAD_OFFSET_MARKER};
use crate::prelude::{InstanceMetadata, DonutBuildResult};
#[cfg(feature="unstable")]
use crate::platform::linux::consts::{PAYLOAD_MARKER_BYTES, STUB_BYTES as STUB_LINUX, TOTAL_LDR_SIZE_PATTERN};
use crate::platform::windows::consts::STUB_BYTES as STUB_WIN;


impl DonutBuildResult {
    /// Returns the final payload array
    pub fn payload(&self) -> &[u8] {
        &self.final_payload
    }

    /// Returns the payload metadata
    pub fn metadata(&self) -> &InstanceMetadata {
        &self.metadata
    }

    /// Returns the packed instance metadata
    pub fn instance(&self) -> &[u8] {
        &self.compressed_instance
    }
}


#[cfg(not(feature="unstable"))]
pub(crate) fn build_unix_shellcode(_instance_bytes: &[u8]) -> DonutResult<Vec<u8>> {
    unimplemented!("the unix payload is unstable. it is not recommended to use it now")
}
#[cfg(feature="unstable")]
pub(crate) fn build_unix_shellcode(instance_bytes: &[u8]) -> DonutResult<Vec<u8>> {
    use az_logger::{error, debug};
    use crate::errors::DonutError;
    let loader_bytes = LOADER_UNIX.to_vec();
    let instance_len = instance_bytes.len();
    let instance_len_bytes = instance_len.to_le_bytes();
    let mut combined_payload = Vec::new();
    combined_payload.extend_from_slice(&loader_bytes);
    combined_payload.extend_from_slice(instance_bytes);
    combined_payload.extend_from_slice(&instance_len_bytes);

    let total_size = combined_payload.len();
    let mut stub = STUB_LINUX.clone().to_vec();
    let payload_marker_offset = stub.windows(PAYLOAD_MARKER_BYTES.len())
        .position(|b| b == PAYLOAD_MARKER_BYTES).ok_or_else(||{
        error!("could not find payload marker offset");
        DonutError::NotFound("payload marker offset".into())
    })?;
    let offset = stub.windows(TOTAL_LDR_SIZE_PATTERN.len()).position(|a| a == TOTAL_LDR_SIZE_PATTERN)
        .ok_or_else(|| {
            error!("Could not find pattern in template.");
            DonutError::BuildError("could not find pattern in template".into())
        })?;
    debug!("Offset: {offset}");
    let patch_start = offset + 2;
    let patch_end = patch_start + 8;
    if patch_end > stub.len() {
        error!("Patch location is out of bounds in the stub!");
        return Err(DonutError::BuildError("patch location is out of bounds in the stub".into()));
    }
    let dest = &mut stub[patch_start..patch_end];
    let size_bytes = (total_size as u64).to_le_bytes();
    dest.copy_from_slice(&size_bytes);
    let mut final_shellcode = Vec::new();
    let patched_stub = &stub[0..payload_marker_offset];
    final_shellcode.extend_from_slice(patched_stub);
    final_shellcode.extend_from_slice(PAYLOAD_MARKER_BYTES);
    final_shellcode.extend_from_slice(&combined_payload);
    Ok(final_shellcode)
}


pub(crate) fn build_windows_shellcode(instance_bytes: &[u8]) -> DonutResult<Vec<u8>> {
    let mut stub = STUB_WIN.to_vec();
    let (loader_bytes, entry_offset) = extract_info()?;
    let loader_call_offset = stub.len() + entry_offset;
    let payload_offset = stub.len() + loader_bytes.len();
    let payload_len = instance_bytes.len();

    patch_marker(&mut stub, &PAYLOAD_LEN_MARKER, &payload_len.to_le_bytes())?;
    patch_marker(
        &mut stub,
        &PAYLOAD_OFFSET_MARKER,
        &payload_offset.to_le_bytes(),
    )?;
    patch_marker(
        &mut stub,
        &LOADER_ENTRY_OFFSET_MARKER,
        &loader_call_offset.to_le_bytes(),
    )?;
    let mut shellcode = stub;
    shellcode.extend_from_slice(&loader_bytes);
    shellcode.extend_from_slice(instance_bytes);
    Ok(shellcode)
}

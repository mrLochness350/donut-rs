#[cfg(feature = "std")]
use crate::errors::{DonutError, DonutResult};
#[cfg(feature = "std")]
use crate::instance::idefs::{DonutEmbeddedInstance, DonutHttpInstance, DonutInstanceStub};
#[cfg(feature = "std")]
use crate::types::enums::InstanceType;
#[cfg(feature = "std")]
use crate::utils::globals::FromBytes;


#[cfg(feature = "std")]
impl DonutInstanceStub {

    /// Writes the stub into a string for displaying it
    pub fn display(&self) -> Result<String, std::fmt::Error> {
        use std::fmt::Write;
        let mut out = String::new();
        writeln!(out, "* DonutInstancesStub:")?;
        writeln!(out, " - Version: {}", self.version)?;
        writeln!(out, " - Instance Size: {}", self.instance_size)?;
        writeln!(out, " - Instance Type: {:?}", self.instance_type)?;
        writeln!(out, " - Instance Type Data Size: {} bytes", self.instance_type_data.len())?;
        writeln!(
            out,
            " - Crypto Present: {}",
            if self.instance_crypt.is_some() { "Yes" } else { "No" }
        )?;
        writeln!(out, " - CRC32: 0x{:08x}", self.instance_crc32)?;
        writeln!(out, " - Compression Settings: {:?}", self.instance_compression_settings)?;

        Ok(out)
    }

    /// Gets the instance bytes from a given stub
    pub fn get_instance_bytes(&self) -> DonutResult<Vec<u8>> {
        match self.instance_type {
            InstanceType::Http => {
                let http = DonutHttpInstance::from_bytes(&self.instance_type_data)?;
                http.get_bytes()
            },
            InstanceType::Embedded => {
                let embedded = DonutEmbeddedInstance::from_bytes(&self.instance_type_data)?;
                embedded.get_bytes()
            },
        }
    }
}


#[cfg(feature = "std")]
impl DonutHttpInstance {
    /// Creates a new [`DonutHttpInstance`] object
    pub fn new(
        address: impl Into<String>,
        endpoint: Option<impl Into<String>>,
        retry_count: u32,
        request_method: Option<impl Into<String>>,
        ignore_certs: bool
    ) -> Self {
        Self {
            retry_count,
            ignore_certs,
            username: None,
            password: None,
            address: address.into(),
            request_method: request_method.map(Into::into),
            payload_endpoint: endpoint.map(Into::into),
        }
    }
    fn generate_payload_url(&self) -> Option<String> {
        match (&self.address, &self.payload_endpoint) {
            (address, Some(payload)) => Some(crate::utils::globals::build_http_url(address, &std::path::PathBuf::from(payload.clone()))),
            _ => None,
        }
    }

    /// Uses `reqwest` to download the instance from the parameters passed to `self`
    pub fn get_bytes(&self) -> DonutResult<Vec<u8>> {
        use reqwest::blocking::Client;
        use reqwest::{Method, Url};
        use std::str::FromStr;
        let client = Client::new();

        let method = self.request_method
            .as_deref()
            .unwrap_or("GET");

        let method = Method::from_str(method)
            .map_err(|e| DonutError::Unknown { e: e.to_string() })?;
        let address = self.generate_payload_url().ok_or(DonutError::InvalidParameter)?;
        let url = Url::from_str(&address)
            .map_err(|e| DonutError::Unknown { e: e.to_string() })?;

        let mut request = client.request(method, url);

        if let Some(ref username) = self.username {
            request = request.basic_auth(username, self.password.clone());
        }

        let response = request
            .send()
            .map_err(|e| DonutError::Unknown { e: e.to_string() })?;

        let bytes = response
            .bytes()
            .map_err(|e| DonutError::Unknown { e: e.to_string() })?;

        Ok(bytes.to_vec())
    }
}

#[cfg(feature = "std")]
impl DonutEmbeddedInstance {
    /// Returns the embedded payload's bytes
    pub fn get_bytes(&self) -> DonutResult<Vec<u8>> {
        Ok(self.payload.clone())
    }
}
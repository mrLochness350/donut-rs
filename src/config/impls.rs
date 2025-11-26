use std::fs;
use std::path::PathBuf;
use az_logger::{debug, error};
use crate::config::preprocessor::ConfigPreprocessor;
use crate::crypto::crypt::DonutCrypto;
use crate::DONUT_API_VERSION;
use crate::instance::{DonutInstance, DonutModule};
use crate::types::enums::{AmsiBypassTechnique, ExitMethod};
use crate::errors::{DonutError, DonutResult};
use crate::prelude::{CompressionSettings, CryptoOptions, DonutConfig};
use crate::types::structs::{AmsiBypass, ApiTable, AvBypassOptions, EtwBypass};

impl DonutConfig {
    /// Creates a [`DonutConfig`] from a configuration file
    pub fn with_config_file(path: impl Into<PathBuf>) -> DonutResult<Self> {
        let path = path.into();
        debug!("Reading config file {}", &path.display());
        let content = fs::read_to_string(&path).map_err(|e| {
            error!("Failed to read config file: {}", e);
            DonutError::Io(e.to_string())
        })?;
        let cfg_p = ConfigPreprocessor::new();

        let processed = match path.extension().and_then(|s| s.to_str()) {
            Some("toml") => cfg_p.process_raw(&content, true),
            Some("json") => cfg_p.process_raw(&content, false),
            _ => Err(DonutError::InvalidFormat),
        }?;
        serde_json::from_value(processed).map_err(|e| {
            error!("Failed to parse config file: {}", e);
            DonutError::SerializationError(e.to_string())
        })
    }

    /// Creates a new instance from the config
    pub fn new_instance(&self) -> DonutResult<DonutInstance> {
        let amsi_bypass = self.bypass_options.amsi_bypass_technique.as_ref().map(|amsi| AmsiBypass::new(amsi.clone(), !matches!(&amsi, AmsiBypassTechnique::None)));
        let etw_bypass = self.bypass_options.etw_bypass_technique.as_ref().map(|etw| EtwBypass::new(etw.clone()));
        let av_bypass_opts = AvBypassOptions {
            patch_syscall_gate: self.bypass_options.patch_syscall_gate,
            amsi_bypass,
            etw_bypass,
        };
        let module = DonutModule::new_from_config(self)?;
        Ok(DonutInstance {
            av_bypass_options: Some(av_bypass_opts),
            instance_entropy: self.bypass_options.entropy_level.clone(),
            exit_method: self.exec_options.exit_method.clone().unwrap_or(ExitMethod::ExitThread),
            decoy_path: self.exec_options.decoy_path.clone(),
            version: DONUT_API_VERSION,
            instance_type: self.build_options.instance_type.clone(),
            donut_http_instance: self.http_options.clone(),
            donut_embedded_instance: self.embedded_options.clone(),
            stub: None,
            donut_module: Some(module),
            api_table: ApiTable::default(),
            donut_mod_bytes: Vec::new(),
            decoy_args: self.exec_options.decoy_args.clone(),
            module_crypto: None,
            module_compression_settings: CompressionSettings::default(),
            module_len: 0,
            module_crc32: 0
        })
    }
}

impl From<CryptoOptions> for DonutCrypto {
    fn from(val: CryptoOptions) -> Self {
        DonutCrypto {
            provider: val.provider,
            key: val.key,
            iv: val.iv,
        }
    }
}
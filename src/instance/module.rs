use alloc::vec::Vec;
#[cfg(feature = "std")]
use crate::{
    compression::compress,
    types::structs::{CompressionSettings, DotnetParameters},
    crypto::crypt::DonutCrypto,
};
#[cfg(feature = "std")]
use az_logger::{info, warn};
#[cfg(feature = "std")]
use azathoth_utils::crc32;
use crate::errors::{DonutResult};
use crate::prelude::{DonutModule};
#[cfg(feature = "std")]
use crate::prelude::{DonutCryptoProvider};
#[cfg(feature = "std")]
use crate::prelude::enums::{CompressionEngine};
use crate::prelude::globals::FromBytes;
use crate::prelude::globals::{ToBytes};

#[cfg(feature = "std")]
impl DonutModule {
    fn new_module(
        file_path: impl Into<std::path::PathBuf>,
        mod_enc: Option<DonutCrypto>,
        compression_settings: Option<CompressionSettings>,
        args: Option<String>,
        dotnet_params: Option<DotnetParameters>,
        function: Option<String>,
    ) -> DonutResult<DonutModule> {
        let path = file_path.into();
        let file_info = crate::fs::file_info::FileInfo::from_path(path)?;
        let dotnet_parameters = match (dotnet_params, file_info.dotnet_parameters) {
            (Some(user_params), Some(file_params)) => Some(DotnetParameters {
                version: file_params.version,
                runtime: match user_params.runtime.as_str() {
                    "" => {
                        warn!(
                            "user_params.donut_rs_internal is empty, defaulting to file params ({})",
                            &file_params.runtime
                        );
                        if file_params.runtime.is_empty() {
                            panic!("file_params.donut_rs_internal should not be empty");
                        }
                        file_params.runtime
                    }
                    _ => user_params.runtime,
                },
                domain: user_params.domain,
                class: user_params.class,
                method: user_params.method,
                args: user_params.args,
            }),
            (None, Some(params)) => Some(params),
            _ => None,
        };

        Ok(DonutModule {
            dotnet_parameters,
            args,
            compression_settings,
            function,
            file_crc32: crc32(&file_info.file_bytes),
            mod_type: file_info.file_type,
            mod_crypto: mod_enc,
            orig_file_size: file_info.size as u32,
            file_bytes: file_info.file_bytes,
            oep: file_info.entry,
        })
    }

    /// Creates a new [`DonutModule`] object from a given [`DonutConfig`](crate::config::structs::DonutConfig) object
    ///
    /// Usable only in the API and CLI
    pub fn new_from_config(cfg: &crate::prelude::DonutConfig) -> DonutResult<Self> {
        let settings = CompressionSettings::new(
            cfg.build_options.compression_engine.clone(),
            cfg.build_options.compression_level.clone(),
        );
        if let Some(dotnet_cfg) = &cfg.dotnet_options {
            let dotnet_params = DotnetParameters {
                runtime: dotnet_cfg.runtime.clone().unwrap_or_default(),
                class: dotnet_cfg.class.clone().unwrap_or_else(|| "Program".into()),
                method: dotnet_cfg.method.clone().unwrap_or_else(|| "Main".into()),
                domain: dotnet_cfg
                    .domain
                    .clone()
                    .unwrap_or_else(|| "v4.0.30319".into()),
                version: dotnet_cfg
                    .version
                    .clone()
                    .unwrap_or_else(|| "v4.0.30319".into()),
                args: dotnet_cfg.args.clone().unwrap_or_default(),
            };
            Self::new_module(
                &cfg.input_file,
                cfg.crypto_options.clone().map(|a| a.into()),
                Some(settings),
                cfg.exec_options.args.clone(),
                Some(dotnet_params),
                cfg.exec_options.function.clone(),
            )
        } else {
            Self::new_module(
                &cfg.input_file,
                cfg.crypto_options.clone().map(|a| a.into()),
                Some(settings),
                cfg.exec_options.args.clone(),
                None,
                cfg.exec_options.function.clone(),
            )
        }
    }

    /// Packs the current module into a vector of bytes
    pub fn pack_module(&mut self, inst: &mut crate::prelude::DonutInstance) -> DonutResult<Vec<u8>> {
        let mut module_bytes = self.build()?;
        info!("module_bytes.len() = {}", module_bytes.len());
        let mut encrypted_bytes = module_bytes.clone();
        if let Some(c) = &self.mod_crypto && !matches!(c.provider, DonutCryptoProvider::None) {
            let crypto: DonutCrypto = c.clone();
            inst.module_crypto = Some(crypto.clone());
            info!("Encrypting module with key: {}, iv:{}", hex::encode(&crypto.key), hex::encode(&crypto.iv));
            encrypted_bytes = crypto.encrypt(&mut module_bytes)?;
        }
        let mut compressed_bytes = encrypted_bytes.clone();
        if let Some(cs) = &mut self.compression_settings && !matches!(cs.compression_engine, CompressionEngine::None) {
            compressed_bytes = compress(cs, encrypted_bytes.as_slice())?;
            inst.module_compression_settings = cs.clone();
        }
        inst.module_len = module_bytes.len() as u32;
        inst.module_crc32 = crc32(&module_bytes);
        Ok(compressed_bytes)
    }
}

impl DonutModule {
    /// Builds the encoded byte array of the module
    pub fn build(&self) -> DonutResult<Vec<u8>> {
        let module = self.to_bytes()?;
        let mlen = module.len() as u32;
        let file_bytes = self.file_bytes.clone();
        let mut v = Vec::new();
        v.extend_from_slice(&mlen.to_le_bytes());
        v.extend_from_slice(&module);
        v.extend_from_slice(&file_bytes);
        Ok(v)
    }

    /// Creates a Donut module from a vector of bytes.
    ///
    /// Essentially reverses the operation done by [`DonutModule::build`]
    //TODO: rename?
    pub fn derive(data: &[u8]) -> DonutResult<Self> {
        let (len_bytes, rest) = data.split_at(size_of::<u32>());
        let msize = u32::from_le_bytes(len_bytes.try_into().unwrap());
        let (module, fbytes) = rest.split_at(msize as usize);
        let mut module = DonutModule::from_bytes(module)?;
        module.file_bytes = fbytes.to_vec();
        Ok(module)
    }
}
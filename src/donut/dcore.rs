use crate::builder::bcore::{build_unix_shellcode, build_windows_shellcode};
use crate::builder::utils::build_stub_bootstrap;
use crate::compression::compress;
use crate::crypto::crypt::DonutCrypto;
use crate::crypto::helpers::{md5, sha256, xor};
use crate::donut::ddefs::Donut;
use crate::errors::{DonutError, DonutResult};
use crate::instance::{
    DonutEmbeddedInstance, DonutInstance, DonutInstanceStub, InstanceInformation,
    InstanceMetadata,
};
use crate::prelude::globals::{
    gen_seed, generate_unix_hashes, generate_windows_hashes, write_to_file, ToBytes,
};
use crate::prelude::{ApiTable, CompressionSettings, DonutBuildResult, DonutConfig, DonutCryptoProvider, DonutValidFileType, FileInfo, InstanceType};
use crate::{DONUT_API_VERSION, DONUT_DEBUG_INSTANCE_VERSION};
use az_logger::{info,error, warn};
use azathoth_utils::crc32;
use std::io::Write;
use crate::prelude::enums::CompressionEngine;

impl Donut {
    /// Creates a new [`Donut`] object
    ///
    /// Requires a [`DonutConfig`] object.
    pub fn new(cfg: &DonutConfig) -> DonutResult<Self> {
        let file_info = FileInfo::from_path(cfg.input_file.clone()).map_err(|e| {
            DonutError::Io(format!(
                "failed to get FileInfo for {}: {}",
                &cfg.input_file.display(),
                e
            ))
        })?;
        let conf = Self {
            file_info,
            instance_information: InstanceInformation::default(),
            config: cfg.clone(),
            final_payload: Vec::new(),
            http_payload: None,
        };
        conf.assertions()?;
        Ok(conf)
    }

    /// Builds the final Donut payload from the configuration.
    ///
    /// This is the main entry point for generating shellcode. Generation steps:
    /// 1. Create a `DonutInstance` from the configuration.
    /// 2. Pack the payload module.
    /// 3. Pack the instance.
    /// 4. Build and prepend loader stub.
    ///
    /// # Returns
    /// A [`DonutBuildResult`] struct containing the final payload, metadata, and packed instance.
    pub fn build(&mut self) -> DonutResult<DonutBuildResult> {
        let mut inst = self.config.new_instance()?;
        let seed = self
            .config
            .debug_options
            .instance_seed
            .unwrap_or(gen_seed());
        inst.donut_mod_bytes = self.pack_module(&mut inst)?;
        let (compressed_bytes, compression_settings) = self.transform_instance(&inst)?;
        let stub = self.build_stub(&inst, seed, &compressed_bytes, compression_settings)?;
        let stub_bytes = stub.to_bytes()?;
        info!("stub_bytes.len() = {}", stub_bytes.len());
        let stub_bootstrap = build_stub_bootstrap(&stub_bytes)?;
        let shellcode = self.build_final_shellcode(stub_bootstrap.clone())?;
        let metadata = self.generate_metadata(&inst, &stub, &stub_bytes, seed, &shellcode)?;
        self.instance_information.packed_instance = stub_bootstrap;
        self.instance_information.instance = inst;
        self.http_payload = Some(stub.instance_type_data.clone());
        self.instance_information.metadata = metadata.clone();
        self.instance_information.compressed_instance = compressed_bytes.clone();
        self.final_payload = shellcode.clone();
        Ok(DonutBuildResult {
            final_payload: shellcode,
            compressed_instance: compressed_bytes,
            metadata,
        })
    }

    /// Saves the data to a file
    pub fn save(&self) -> DonutResult<()> {
        self.save_instance_file()?;
        self.save_final_payload()?;
        self.save_http_output()?;
        if self.config.build_options.emit_metadata {
            self.save_metadata()?;
        }
        Ok(())
    }

    fn assertions(&self) -> DonutResult<()> {
        match self.config.build_options.instance_type {
            InstanceType::Http => {
                if self.config.http_options.is_none() {
                    Err(DonutError::InvalidParameterStr(
                        "http options weren't specified and http instance was selected".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            InstanceType::Embedded => {
                if self.config.embedded_options.is_none() {
                    Err(DonutError::InvalidParameterStr(
                        "embedded options weren't specified and embedded instance was selected"
                            .into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn save_final_payload(&self) -> DonutResult<()> {
        let mut payload_file = write_to_file(self.config.output_file.clone())?;
        payload_file.write_all(&self.final_payload)?;
        Ok(())
    }
    fn save_http_output(&self) -> DonutResult<()> {
        let mut http_file = write_to_file(self.config.http_output.clone())?;
        let bytes = self.http_payload.clone().ok_or(DonutError::BuildError(
            "cannot save empty http payload".into(),
        ))?;
        http_file.write_all(bytes.as_ref())?;
        Ok(())
    }
    fn save_metadata(&self) -> DonutResult<()> {
        let mut metadata_file = write_to_file(self.config.build_options.metadata_output.clone())?;
        let serialized_metadata = serde_json::to_vec_pretty(&self.instance_information.metadata)
            .map_err(|e| DonutError::SerializationError(e.to_string()))?;
        metadata_file.write_all(&serialized_metadata)?;
        Ok(())
    }

    fn save_instance_file(&self) -> DonutResult<()> {
        let mut instance_file = write_to_file(self.config.instance_output.clone())?;
        match self.config.build_options.instance_type {
            InstanceType::Embedded => {
                if self.config.debug_options.prepend_debug_flag {
                    let version = self.instance_information.instance.version.to_le_bytes();
                    instance_file.write_all(DONUT_DEBUG_INSTANCE_VERSION)?;
                    instance_file.write_all(&version)?;
                }
                instance_file.write_all(&self.instance_information.packed_instance)?;
            }
            InstanceType::Http => {
                instance_file.write_all(&self.instance_information.compressed_instance)?;
            }
        }
        Ok(())
    }
    pub(super) fn pack_module(&self, inst: &mut DonutInstance) -> DonutResult<Vec<u8>> {
        info!("Packing module...");
        let mut module = inst.donut_module.clone().ok_or_else(|| {
            error!("Donut module is empty");
            DonutError::ModuleError
        })?;
        info!("module byte len={}", module.file_bytes.len());
        warn!("args exist: {}", module.args.is_some());
        let packed_module = module.pack_module(inst)?;
        Ok(packed_module)
    }

    pub(super) fn transform_instance(
        &self,
        inst: &DonutInstance,
    ) -> DonutResult<(Vec<u8>, CompressionSettings)> {
        let mut instance_bytes = inst.to_bytes()?;
        let mut encrypted_bytes = instance_bytes.clone();
        if let Some(c) = &self.config.crypto_options {
            let crypto: DonutCrypto = c.clone().into();
            if !matches!(crypto.provider, DonutCryptoProvider::None) {
                info!("Encrypting payload with key: {}, iv:{}", hex::encode(&crypto.key), hex::encode(&crypto.iv));
                encrypted_bytes = crypto.encrypt(&mut instance_bytes)?;
            }
        }
        let mut compression = CompressionSettings::new(
            self.config.build_options.compression_engine.clone(),
            self.config.build_options.compression_level.clone(),
        );
        let compressed_bytes = if !matches!(self.config.build_options.compression_engine, CompressionEngine::None) {
            compress(&mut compression, &encrypted_bytes)?
        } else {
            encrypted_bytes
        };
        Ok((compressed_bytes, compression))
    }

    fn build_stub_type(
        &self,
        inst: &DonutInstance,
        compressed_bytes: &[u8],
    ) -> DonutResult<Vec<u8>> {
        match inst.instance_type {
            InstanceType::Http => {
                let http_cfg = inst.donut_http_instance.as_ref().ok_or_else(|| {
                    DonutError::NotFound("could not find http instance settings".into())
                })?;
                let http_bytes = http_cfg.to_bytes()?;
                info!("http_bytes.len()={}",http_bytes.len());
                Ok(http_bytes)
            }
            InstanceType::Embedded => {
                let embedded = DonutEmbeddedInstance {
                    payload: compressed_bytes.to_vec(),
                    payload_size: compressed_bytes.len() as u32,
                    payload_hash: crc32(compressed_bytes),
                };
                embedded.to_bytes()
            }
        }
    }
    pub(super) fn build_stub(
        &self,
        inst: &DonutInstance,
        seed: u32,
        compressed_bytes: &[u8],
        compression: CompressionSettings,
    ) -> DonutResult<DonutInstanceStub> {
        let hashes = match self.file_info.file_type {
            DonutValidFileType::Dll { .. } | DonutValidFileType::PE { .. } => {
                generate_windows_hashes(seed)
            }
            DonutValidFileType::ELF | DonutValidFileType::SharedObject => {
                generate_unix_hashes(seed)
            }
            _ => return Err(DonutError::Unsupported),
        };
        let idata = self.build_stub_type(inst, compressed_bytes)?;
        let instance_type_data= xor(&idata, &[0x66,0x77]);
        let is_dotnet = matches!(
            self.file_info.file_type,
            DonutValidFileType::Dll { dotnet: true } | DonutValidFileType::PE { dotnet: true }
        );
        let instance_crc32 = crc32(inst.to_bytes()?);
        Ok(DonutInstanceStub {
            instance_crc32,
            instance_type_data,
            is_dotnet,
            version: self.config.debug_options.version.unwrap_or(inst.version),
            instance_size: compressed_bytes.len() as u32,
            instance_type: inst.instance_type.clone(),
            instance_crypt: self.config.crypto_options.clone().map(|c| c.into()),
            instance_compression_settings: compression,
            api_table: ApiTable::new(seed, hashes),
        })
    }

    pub(super) fn generate_metadata(
        &self,
        inst: &DonutInstance,
        stub: &DonutInstanceStub,
        stub_bytes: &[u8],
        seed: u32,
        shellcode: &[u8],
    ) -> DonutResult<InstanceMetadata> {
        let host: Option<String> = if let Some(a) = &inst.donut_http_instance {
            let host = format!(
                "{}{}",
                a.address,
                a.payload_endpoint.clone().unwrap_or("/".to_owned())
            );
            Some(host)
        } else {
            None
        };
        Ok(InstanceMetadata {
            seed,
            version: format!("instance.{}", stub.version),
            instance_type: inst.instance_type.clone(),
            encrypted: self.config.crypto_options.is_some(),
            is_dotnet: stub.is_dotnet,
            stub_size: stub_bytes.len() as u32,
            stub_crc: crc32(stub_bytes),
            instance_crc: stub.instance_crc32,
            compressed_size: stub.instance_size,
            module_size: inst.donut_mod_bytes.len() as u32,
            module_crc: crc32(&inst.donut_mod_bytes),
            sha256: hex::encode(sha256(shellcode)),
            md5: hex::encode(md5(shellcode)),
            crc: crc32(shellcode),
            donut_api_version: DONUT_API_VERSION,
            local_file_path: self.config.input_file.clone(),
            uncompressed_size: self.file_info.size as u32,
            stub_server: host,
            ..Default::default()
        })
    }

    pub(super) fn build_final_shellcode(
        &self,
        mut packed_instance: Vec<u8>,
    ) -> DonutResult<Vec<u8>> {
        if matches!(
            self.file_info.file_type,
            DonutValidFileType::Dll { .. } | DonutValidFileType::PE { .. }
        ) {
            let flag = if self.config.exec_options.thread_on_enter {
                1
            } else {
                0
            };
            packed_instance.insert(0, flag);
            build_windows_shellcode(&packed_instance)
        } else if matches!(
            self.file_info.file_type,
            DonutValidFileType::ELF | DonutValidFileType::SharedObject
        ) {
            build_unix_shellcode(&packed_instance)
        } else {
            unimplemented!("script payload support is not yet implemented!")
        }
    }
}

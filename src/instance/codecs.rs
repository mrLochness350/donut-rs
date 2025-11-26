use azathoth_utils::codec::{Codec, Decoder, Encoder};
use azathoth_utils::errors::AzUtilResult;
use crate::instance::{DonutEmbeddedInstance, DonutHttpInstance, DonutInstance, DonutInstanceStub, DonutModule};
use crate::prelude::{ApiTable, CompressionSettings, DonutValidFileType, EntropyLevel, ExitMethod, InstanceType};
use alloc::vec::Vec;
use alloc::string::String;

impl Codec for DonutEmbeddedInstance {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        enc.push_u32(self.payload_size)?;
        enc.push_u32(self.payload_hash)?;
        enc.push_slice(&self.payload)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            payload_size: dec.read_u32()?,
            payload_hash: dec.read_u32()?,
            payload: dec.read_vec()?
        })
    }
}


impl Codec for DonutModule {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.mod_crypto.encode(enc)?;
        self.compression_settings.encode(enc)?;
        self.args.encode(enc)?;
        self.mod_type.encode(enc)?;
        self.dotnet_parameters.encode(enc)?;
        self.oep.encode(enc)?;
        self.file_crc32.encode(enc)?;
        self.orig_file_size.encode(enc)?;
        self.function.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            file_bytes: Vec::new(),
            mod_crypto: Option::decode(dec)?,
            compression_settings: Option::decode(dec)?,
            args: Option::decode(dec)?,
            mod_type: DonutValidFileType::decode(dec)?,
            dotnet_parameters: Option::decode(dec)?,
            oep: u32::decode(dec)?,
            file_crc32: u32::decode(dec)?,
            orig_file_size: u32::decode(dec)?,
            function: Option::decode(dec)?,
        })
    }
}



impl Codec for DonutInstance {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.av_bypass_options.encode(enc)?;
        self.instance_entropy.encode(enc)?;
        self.exit_method.encode(enc)?;
        self.decoy_path.encode(enc)?;
        self.decoy_args.encode(enc)?;
        self.version.encode(enc)?;
        self.instance_type.encode(enc)?;
        self.donut_mod_bytes.encode(enc)?;
        self.module_compression_settings.encode(enc)?;
        self.module_len.encode(enc)?;
        self.module_crypto.encode(enc)?;
        self.module_crc32.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            av_bypass_options: Option::decode(dec)?,
            instance_entropy: EntropyLevel::decode(dec)?,
            exit_method: ExitMethod::decode(dec)?,
            decoy_path: Option::decode(dec)?,
            decoy_args: Option::decode(dec)?,
            version: u32::decode(dec)?,
            instance_type: InstanceType::decode(dec)?,
            donut_http_instance: None,
            donut_embedded_instance: None,
            donut_module: None,
            stub: None,
            api_table: ApiTable::default(),
            donut_mod_bytes: Vec::decode(dec)?,
            module_compression_settings: CompressionSettings::decode(dec)?,
            module_len: u32::decode(dec)?,
            module_crypto: Option::decode(dec)?,
            module_crc32: u32::decode(dec)?,
        })
    }
}


impl Codec for DonutHttpInstance {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.username.encode(enc)?;
        self.password.encode(enc)?;
        self.address.encode(enc)?;
        self.payload_endpoint.encode(enc)?;
        self.retry_count.encode(enc)?;
        self.request_method.encode(enc)?;
        self.ignore_certs.encode(enc)?;
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            username: dec.read_opt::<String>()?,
            password: dec.read_opt::<String>()?,
            address: dec.read_string()?,
            payload_endpoint: dec.read_opt::<String>()?,
            retry_count: dec.read_u32()?,
            request_method: dec.read_opt::<String>()?,
            ignore_certs: dec.read_bool()?,
        })
    }
}

impl Codec for DonutInstanceStub {
    fn encode(&self, enc: &mut Encoder) -> AzUtilResult<()> {
        self.version.encode(enc)?;
        self.instance_size.encode(enc)?;
        self.instance_type.encode(enc)?;
        self.instance_type_data.encode(enc)?;
        self.instance_crypt.encode(enc)?;
        self.instance_crc32.encode(enc)?;
        self.instance_compression_settings.encode(enc)?;
        self.api_table.encode(enc)?;
        self.is_dotnet.encode(enc)?;
        Ok(())
    }
    fn decode(dec: &mut Decoder) -> AzUtilResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            version: u32::decode(dec)?,
            instance_size: u32::decode(dec)?,
            instance_type: InstanceType::decode(dec)?,
            instance_type_data: Vec::decode(dec)?,
            instance_crypt: Option::decode(dec)?,
            instance_crc32: u32::decode(dec)?,
            instance_compression_settings: CompressionSettings::decode(dec)?,
            api_table: ApiTable::decode(dec)?,
            is_dotnet: Option::decode(dec)?.unwrap_or(false),
        })

    }
}
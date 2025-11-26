use std::path::PathBuf;
use crate::compression::enums::{CompressionEngine, CompressionLevel};
use crate::prelude::{BuildOptions, BypassOptions, CryptoOptions, DebugOptions, DonutConfig, DotnetConfiguration, ExecutionOptions};
use crate::fs::file_info::FileInfo;
use crate::instance::{DonutEmbeddedInstance, DonutHttpInstance};
use crate::types::enums::{AmsiBypassTechnique, DonutCryptoProvider, EntropyLevel, EtwBypassTechnique, ExitMethod, InstanceType, OutputFormat};

impl DonutConfig {
    /// Creates a new DonutConfig object for the given file
    #[inline]
    pub fn new(input: impl Into<PathBuf>) -> Self {
        Self {
            input_file: input.into(),
            ..Default::default()
        }
    }

    /// Set the input binary path.
    #[inline]
    pub fn input(mut self, path: impl Into<PathBuf>) -> Self {
        self.input_file = path.into();
        self
    }

    /// Set the final payload output path.
    #[inline]
    pub fn output(mut self, path: Option<impl Into<PathBuf>>) -> Self {
        self.output_file = path.map(|p| p.into());
        self
    }

    /// Set the debug instance output path.
    #[inline]
    pub fn instance_output(mut self, path: Option<impl Into<PathBuf>>) -> Self {
        self.instance_output = path.map(|p| p.into());
        self
    }

    /// Set the HTTP-instance debug output path.
    #[inline]
    pub fn http_output(mut self, path: Option<impl Into<PathBuf>>) -> Self {
        self.http_output = path.map(|p| p.into());
        self
    }

    /// Provide HTTP instance options.
    #[inline]
    pub fn http_options(mut self, opts: Option<DonutHttpInstance>) -> Self {
        self.http_options = opts;
        self
    }

    /// Provide embedded instance options.
    #[inline]
    pub fn embedded_options(mut self, opts: DonutEmbeddedInstance) -> Self {
        self.embedded_options = Some(opts);
        self
    }

    /// Sets the file info for the config
    #[inline]
    pub fn file_info(mut self, opts: FileInfo) -> Self {
        self.file_info = opts;
        self
    }

    /// Provide .NET options.
    #[inline]
    pub fn dotnet_options(mut self, opts: DotnetConfiguration) -> Self {
        self.dotnet_options = Some(opts);
        self
    }

    /// Replace execution options.
    #[inline]
    pub fn exec_options(mut self, opts: ExecutionOptions) -> Self {
        self.exec_options = opts;
        self
    }

    /// Replace debug options.
    #[inline]
    pub fn debug_options(mut self, opts: DebugOptions) -> Self {
        self.debug_options = opts;
        self
    }

    /// Replace build options.
    #[inline]
    pub fn build_options(mut self, opts: BuildOptions) -> Self {
        self.build_options = opts;
        self
    }

    /// Replace crypto options.
    #[inline]
    pub fn crypto_options(mut self, opts: CryptoOptions) -> Self {
        self.crypto_options = Some(opts);
        self
    }

    /// Replace bypass options.
    #[inline]
    pub fn bypass_options(mut self, opts: BypassOptions) -> Self {
        self.bypass_options = opts;
        self
    }

    /// Mutate execution options in-place using a closure.
    #[inline]
    pub fn with_exec(mut self, f: impl FnOnce(&mut ExecutionOptions)) -> Self {
        f(&mut self.exec_options);
        self
    }

    /// Mutate debug options in-place using a closure.
    #[inline]
    pub fn with_debug(mut self, f: impl FnOnce(&mut DebugOptions)) -> Self {
        f(&mut self.debug_options);
        self
    }

    /// Mutate build options in-place using a closure.
    #[inline]
    pub fn with_build(mut self, f: impl FnOnce(&mut BuildOptions)) -> Self {
        f(&mut self.build_options);
        self
    }

    /// Mutate crypto options in-place using a closure.
    #[inline]
    pub fn with_crypto(mut self, f: impl FnOnce(&mut Option<CryptoOptions>)) -> Self {
        f(&mut self.crypto_options);
        self
    }

    /// Mutate bypass options in-place using a closure.
    #[inline]
    pub fn with_bypass(mut self, f: impl FnOnce(&mut BypassOptions)) -> Self {
        f(&mut self.bypass_options);
        self
    }

    /// Mutate or create the .NET options in-place using a closure.
    #[inline]
    pub fn with_dotnet(mut self, f: impl FnOnce(&mut DotnetConfiguration)) -> Self {
        if self.dotnet_options.is_none() {
            self.dotnet_options = Some(DotnetConfiguration::default());
        }
        f(self.dotnet_options.as_mut().unwrap());
        self
    }

    /// Mutate or create HTTP options in-place using a closure.
    #[inline]
    pub fn with_http(mut self, f: impl FnOnce(&mut DonutHttpInstance)) -> Self {
        if self.http_options.is_none() {
            self.http_options = Some(DonutHttpInstance::default());
        }
        f(self.http_options.as_mut().unwrap());
        self
    }

    /// Mutate or create Embedded options in-place using a closure.
    #[inline]
    pub fn with_embedded(mut self, f: impl FnOnce(&mut DonutEmbeddedInstance)) -> Self {
        if self.embedded_options.is_none() {
            self.embedded_options = Some(DonutEmbeddedInstance::default());
        }
        f(self.embedded_options.as_mut().unwrap());
        self
    }
}

impl ExecutionOptions {
    /// Creates a new [`ExecuteOptions`](ExecutionOptions) object
    #[inline] pub fn new() -> Self { Self::default() }
    /// Create a new thread when entering the loader
    #[inline] pub fn thread_on_enter(mut self, v: bool) -> Self { self.thread_on_enter = v; self }
    /// Uses the given path as a decoy
    #[inline] pub fn decoy_path(mut self, s: Option<impl Into<String>>) -> Self { self.decoy_path = s.map(|s| s.into()); self }
    /// Uses te given args as a decoy
    #[inline] pub fn decoy_args(mut self, s: Option<impl Into<String>>) -> Self { self.decoy_args = s.map(|s| s.into()); self }
    /// Sets the loaded binary args
    #[inline] pub fn args(mut self, s: Option<impl Into<String>>) -> Self { self.args = s.map(|s| s.into()); self}
    /// Sets the loader exit method
    #[inline] pub fn exit_method(mut self, m: Option<ExitMethod>) -> Self { self.exit_method = m; self }
    /// Sets the args to pass to the loader
    #[inline] pub fn args_str(mut self, s: Option<impl Into<String>>) -> Self { self.args = s.map(|s| s.into()); self }
    /// Sets the function to execute
    #[inline] pub fn function(mut self, s: Option<impl Into<String>>) -> Self { self.function = s.map(|s| s.into()); self }
}

impl DebugOptions {
    /// Creates a new [`DebugOptions`] object
    #[inline] pub fn new() -> Self { Self::default() }
    /// Tells the builder to prepend the debug flag to the instance
    #[inline] pub fn prepend_debug_flag(mut self, v: bool) -> Self { self.prepend_debug_flag = v; self }
    /// Sets the instance version
    #[inline] pub fn version(mut self, v: Option<u32>) -> Self { self.version = v; self }
    /// Manually assigns a seed to use for hashing instead of using a random seed
    #[inline] pub fn instance_seed(mut self, v: Option<u32>) -> Self { self.instance_seed = v; self }
    /// Cleans the output directory on rerun
    #[inline] pub fn clean_output_dir(mut self, v: bool) -> Self { self.clean_output_dir = v; self }
}

impl BuildOptions {
    /// Creates a new [`BuildOptions`] object
    #[inline] pub fn new() -> Self { Self::default() }
    /// Decodes the module (in memory) after encoding it to validate that its correct
    #[inline] pub fn assert_module_integrity(mut self, v: bool) -> Self { self.assert_module_integrity = v; self }
    /// Emit build metadata
    #[inline] pub fn emit_metadata(mut self, v: bool) -> Self { self.emit_metadata = v; self }
    /// Path to metadata
    #[inline] pub fn metadata_output(mut self, p: Option<impl Into<PathBuf>>) -> Self { self.metadata_output = p.map(|p| p.into()); self }
    /// Instance type to use
    #[inline] pub fn instance_type(mut self, t: InstanceType) -> Self { self.instance_type = t; self }
    /// Compression level to use
    #[inline] pub fn compression_level(mut self, l: CompressionLevel) -> Self { self.compression_level = l; self }
    /// Compression engine to use
    #[inline] pub fn compression_engine(mut self, e: CompressionEngine) -> Self { self.compression_engine = e; self }
    /// Output format to use
    #[inline] pub fn output_format(mut self, f: OutputFormat) -> Self { self.output_format = f; self }
}

impl CryptoOptions {
    /// Creates a new [`CryptoOptions`] object
    #[inline] pub fn new() -> Self { Self::default() }
    /// Sets the key to use for the encryption/decryption process
    #[inline] pub fn key(mut self, k: Vec<u8>) -> Self { self.key = k; self }
    /// Sets the IV to use for the encryption/decryption process
    #[inline] pub fn iv(mut self, iv: Vec<u8>) -> Self { self.iv = iv; self }
    /// Sets the crypto provider for the encryption/decryption process
    #[inline] pub fn provider(mut self, p: DonutCryptoProvider) -> Self { self.provider = p; self }
}

impl BypassOptions {
    /// Creates a new [`BypassOptions`] object
    #[inline] pub fn new() -> Self { Self::default() }
    /// Attempts to disable WDAC (Windows Defender Application Control)
    #[inline] pub fn disable_wdac(mut self, v: bool) -> Self { self.disable_wdac = v; self }
    /// Attempts to detect and patch any syscall hooks
    #[inline] pub fn patch_syscall_gate(mut self, v: bool) -> Self { self.patch_syscall_gate = v; self }
    /// Sets the AMSI bypass technique to use
    #[inline] pub fn amsi_bypass_technique(mut self, t: Option<AmsiBypassTechnique>) -> Self { self.amsi_bypass_technique = t; self }
    /// Sets the ETW (Event Tracing for Windows) bypass method
    #[inline] pub fn etw_bypass_technique(mut self, t: Option<EtwBypassTechnique>) -> Self { self.etw_bypass_technique = t; self }
    /// Sets the global entropy level to use
    #[inline] pub fn entropy_level(mut self, e: EntropyLevel) -> Self { self.entropy_level = e; self }
}

impl DotnetConfiguration {
    /// Creates a new [`DotnetConfiguration`] object
    #[inline] pub fn new() -> Self { Self::default() }
    /// Sets the .NET runtime to use
    #[inline] pub fn runtime(mut self, s: Option<impl Into<String>>) -> Self { self.runtime = s.map(|s|s.into()); self }
    /// Sets the .NET domain to use
    #[inline] pub fn domain(mut self, s: Option<impl Into<String>>) -> Self { self.domain = s.map(|s|s.into()); self }
    /// Sets the class to use
    #[inline] pub fn class(mut self, s: Option<impl Into<String>>) -> Self { self.class = s.map(|s|s.into()); self }
    /// Sets the method to invoke
    #[inline] pub fn method(mut self, s: Option<impl Into<String>>) -> Self { self.method = s.map(|s|s.into()); self }
    /// Sets the preferred .NET version
    #[inline] pub fn version(mut self, s: Option<impl Into<String>>) -> Self { self.version = s.map(|s|s.into()); self }

    /// Replace args with a vector.
    #[inline] pub fn args_vec(mut self, v: Vec<String>) -> Self { self.args = Some(v); self }

    /// Append a single arg (allocates `args` if absent).
    #[inline]
    pub fn arg(mut self, s: impl Into<String>) -> Self {
        match &mut self.args {
            Some(v) => v.push(s.into()),
            None => self.args = Some(vec![s.into()]),
        }
        self
    }

    /// Sets the argument vector
    #[inline]
    pub fn args(mut self, s: Option<impl Into<Vec<String>>>) -> Self {
        self.args = s.map(|s|s.into());
        self
    }
}
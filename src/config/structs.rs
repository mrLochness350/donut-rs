use crate::utils::globals::de_hex2vec;
use std::path::PathBuf;
use crate::compression::enums::{CompressionEngine, CompressionLevel};
use crate::fs::file_info::FileInfo;
use crate::instance::{DonutEmbeddedInstance, DonutHttpInstance};
use crate::types::enums::{AmsiBypassTechnique, DonutCryptoProvider, EntropyLevel, EtwBypassTechnique, ExitMethod, InstanceType, OutputFormat};

/// Top-level configuration for building a Donut instance.
///
/// This struct aggregates all user-controllable settings for the builder,
/// including input/output paths, instance type, compression/crypto, debug
/// behavior, and AV/telemetry bypass strategies.
///
/// **Note:** Most fields are crate-private; external callers should prefer
/// the crate’s builder API (e.g., `DonutConfig::new()` and setter methods)
/// rather than constructing this directly.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DonutConfig {
    /// Path to the target binary (PE/ELF/.NET assembly) to package.
    pub(crate) input_file: PathBuf,

    /// If set, write the constructed **instance blob** to this path for debugging.
    pub(crate) instance_output: Option<PathBuf>,

    /// If set, write the final **payload** to this path.
    pub(crate) output_file: Option<PathBuf>,

    /// If set, write the HTTP-mode instance payload to this path.
    pub(crate) http_output: Option<PathBuf>,

    #[serde(skip)]
    /// Discovered metadata about the input file (format, arch, entry, etc.).
    pub(crate) file_info: FileInfo,

    /// Options specific to the HTTP transport instance (if used).
    ///
    /// `None` disables HTTP instance generation.
    pub(crate) http_options: Option<DonutHttpInstance>,

    /// Options specific to the embedded (in-memory) instance (if used).
    ///
    /// `None` disables embedded instance generation.
    pub(crate) embedded_options: Option<DonutEmbeddedInstance>,

    /// Configuration for .NET payloads (only applicable when the input is .NET).
    pub(crate) dotnet_options: Option<DotnetConfiguration>,

    /// Loader execution behavior (arguments, entry function, exit strategy, etc.).
    pub(crate) exec_options: ExecutionOptions,

    /// Debug/diagnostic behavior during build and emission.
    pub(crate) debug_options: DebugOptions,

    /// Build pipeline options (instance type, compression, metadata emission).
    pub(crate) build_options: BuildOptions,

    /// Cryptographic settings applied to the instance/payload.
    pub(crate) crypto_options: Option<CryptoOptions>,

    /// AV and telemetry bypass strategies.
    pub(crate) bypass_options: BypassOptions,
}

/// Execution behavior for the produced loader/instance.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionOptions {
    /// If `true`, execute in a dedicated thread upon entry (platform-dependent).
    pub(crate) thread_on_enter: bool,

    /// Optional decoy executable path to present to tooling/environment.
    pub(crate) decoy_path: Option<String>,

    /// Optional decoy command-line arguments.
    pub(crate) decoy_args: Option<String>,

    /// How the loader should terminate once finished (if applicable).
    pub(crate) exit_method: Option<ExitMethod>,

    /// Argument string passed to the payload/entry point (format is payload-specific).
    pub(crate) args: Option<String>,

    /// Name of the function/method to invoke as the payload entry (payload-specific).
    pub(crate) function: Option<String>,
}

/// Debug/diagnostic behavior toggles and overrides.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugOptions {
    /// If `true`, prepend the `DONUT_DEBUG_INSTANCE_VERSION` flag to the instance
    /// for easier on-disk discovery during debugging.
    ///
    /// Note: this may increase detectability and should not be enabled in production.
    pub(crate) prepend_debug_flag: bool,

    /// Override the instance version used during build (defaults to crate’s current API version).
    pub(crate) version: Option<u32>,

    /// Override the hash seed used when generating instance identifiers.
    pub(crate) instance_seed: Option<u32>,

    /// If `true`, remove any existing output directory/files before emitting artifacts.
    pub(crate) clean_output_dir: bool,
}

/// Build pipeline configuration.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct BuildOptions {
    /// If `true`, verify the integrity of the assembled module prior to emission.
    pub(crate) assert_module_integrity: bool,

    /// If `true`, emit build metadata alongside artifacts.
    pub(crate) emit_metadata: bool,

    /// Where to write metadata when `emit_metadata` is enabled.
    pub(crate) metadata_output: Option<PathBuf>,

    /// The instance wrapper to produce (embedded/HTTP).
    pub(crate) instance_type: InstanceType,

    /// Compression level applied to the payload (exact effect depends on engine).
    pub(crate) compression_level: CompressionLevel,

    /// Compression engine to use.
    pub(crate) compression_engine: CompressionEngine,

    /// Output format
    pub(crate) output_format: OutputFormat
}

/// Cryptographic settings for produced artifacts.
///
/// Essentially just a clone of the [`DonutCrypto`](crate::crypto::crypt::DonutCrypto) struct
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct CryptoOptions {
    /// Key value (32 bytes)
    #[serde(deserialize_with="de_hex2vec")]
    pub key: Vec<u8>,
    /// IV Value (16 bytes)
    #[serde(deserialize_with="de_hex2vec")]
    pub iv: Vec<u8>,
    /// Crypto provider
    pub provider: DonutCryptoProvider
}

/// AV and telemetry bypass configuration.
///
/// These options influence runtime behavior and may be platform/version-dependent.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct BypassOptions {
    /// Attempt to disable Windows Defender Application Control (WDAC) where applicable.
    pub(crate) disable_wdac: bool,

    /// Attempt to patch/avoid syscall gates (if present) for direct system call usage.
    pub(crate) patch_syscall_gate: bool,

    /// AMSI bypass technique to apply (Windows-only).
    pub(crate) amsi_bypass_technique: Option<AmsiBypassTechnique>,

    /// ETW bypass technique to apply (Windows-only).
    pub(crate) etw_bypass_technique: Option<EtwBypassTechnique>,

    /// Global entropy target for emissions (affects packing/obfuscation where supported).
    pub(crate) entropy_level: EntropyLevel,
}

/// Configuration parameters for the .NET loader (when the input is .NET).
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DotnetConfiguration {
    /// .NET runtime to use (if available); `None` uses the default probing behavior.
    pub(crate) runtime: Option<String>,

    /// .NET domain to use.
    pub(crate) domain: Option<String>,

    /// Fully qualified class name to invoke.
    pub(crate) class: Option<String>,

    /// Method to invoke on `class`.
    pub(crate) method: Option<String>,

    /// Target .NET version (e.g., `v4.0.30319`); use `None` to auto-detect.
    pub(crate) version: Option<String>,

    /// Arguments to pass to the .NET entry method.
    pub(crate) args: Option<Vec<String>>,
}
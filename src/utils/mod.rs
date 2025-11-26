//! This file defines the publicly available and internal modules for this crate.
//! Each module provides specific functionality, supporting the overall features of the project.
//! Submodules:
//!
//! - [`globals`]

/// Global helper functions.
///
/// Contains reusable helper functions that provide
/// commonly used functionality across different modules.
pub mod globals;

/// Cross-platform argument parser for the module
///
/// Exports [`split_args`](argparse::split_args)
pub mod argparse;
/// Contains formatter code to convert bytes to different formats
#[cfg(feature = "std")]
pub mod formatters;
/// Hashes a given function name or list of functions with a seed
#[cfg(feature = "std")]
pub mod hash_generator;
/// Converts an executable file to a binary blob with a given format
#[cfg(feature = "std")]
pub mod exe_to_bin;
#[cfg(feature = "loader")]
/// Minor utilities used by the loaders
pub mod loader_utils;
// #[cfg(feature = "logging")]
/// Logging API
pub mod log_wrapper;
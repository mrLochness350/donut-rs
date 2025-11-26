//! # Donut Loader API
//!
//! Public API for configuring and building Donut instances.
//!
//! ## Example
//!
//! ```rust
//! use std::io;
//! use libdonut_rs::{Donut, DonutConfig, DonutHttpInstance};
//!
//! fn main() -> io::Result<()> {
//!     let http_opts = DonutHttpInstance::new("http://127.0.0.1:9001", Some("/payload.bin"), 5, Some("GET"), false);
//!     let cfg = DonutConfig::new("C:\\Windows\\System32\\calc.exe").http_options(Some(http_opts));
//!     println!("Created config: {cfg:?}");
//!
//!     let mut donut = Donut::new(&cfg)?;
//!     println!("Created donut object");
//!     let bp = donut.build()?;
//!     println!("Finished building donut object");
//!
//!     let payload = bp.payload();
//!     let metadata = bp.metadata();
//!     println!("Metadata: {metadata:?}");
//!     println!("Payload size: {}", payload.len());
//!     Ok(())
//! }
//! ```
//! ## Versioning
//!
//! - API version 5 is the current ([`DONUT_API_VERSION`]).
//!
//! ## Notes
//!
//! - This crate is under active development. APIs may change.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature="loader")]
extern crate core;

/// Crate-wide error types.
mod errors;

/// Platform-specific bindings, structs, and types.
mod platform;

/// Common structs, types, and enums used across components.
mod types;

/// Public instance API.
mod instance;

/// Internal utilities.
mod utils;

/// Builder API (std-only).
#[cfg(feature = "std")]
mod builder;

/// Compression utilities
mod compression;

/// Donut configuration code (std-only)
#[cfg(feature = "std")]
mod config;

/// Cryptographic helpers and utilities
mod crypto;

/// Filesystem utilities (std-only)
#[cfg(feature = "std")]
mod fs;
/// Module re-exports
pub mod prelude;
#[cfg(feature = "std")]
mod donut;

/// API version const
pub const DONUT_API_VERSION: u32 = 5;

/// Header value for the instance (debug mode)
pub const DONUT_DEBUG_INSTANCE_VERSION: &[u8; 23] = b"DONUT_INSTANCE_VERSION=";
#[cfg(feature = "std")]
pub use prelude::{Donut, DonutConfig, DonutInstanceStub, DonutHttpInstance};
pub use prelude::{DonutModule, DonutInstance,DonutResult, DonutError};
#[cfg(feature = "std")]
pub use crate::{
    fs::file_info::FileInfo,
    donut::*,
    config::{structs::*,impls},
    utils::{hash_generator, exe_to_bin, formatters},
    platform::windows::loader_win,
    builder::bdefs::DonutBuildResult
};

pub use crate::{
    crypto::*,
    compression::*,
    instance::*,
    utils::log_wrapper::*,
    errors::{DonutError, DonutResult},
    types::{enums::*, structs::*},
    utils::{globals, argparse},
};

#[cfg(all(feature = "loader", target_os = "windows"))]
pub use crate::{
    platform::windows::{consts, url_context, fn_defs},
    utils::loader_utils::{GLOBAL_ALLOCATOR, tnoret, ShellcodeLoader, resolve},
};

#[cfg(all(feature = "loader", target_os = "linux", feature = "unstable"))]
pub use crate::platform::linux::{utils, consts, types, fn_defs};
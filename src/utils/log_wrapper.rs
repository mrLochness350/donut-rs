#[cfg(feature = "std")]
use az_logger::{Color, LogFormatStyle, LogFormatStyles, Logger, LoggerOptions, Style};
/// Logger handle re-export (when `logging` is enabled).
#[cfg(feature = "logging")]
pub use azathoth_logger::LOG;

#[cfg(feature = "std")]
/// Initialize logging (temporary API).
///
/// This configures `az_logger` with custom styles. Subject to removal in a future release.
pub fn init_log(no_console: bool) -> crate::errors::DonutResult<()> {
    let custom_log_styles = LogFormatStyles {
        error: LogFormatStyle {
            fg: Some(Color::BrightRed),
            bg: None,
            style: Style::default().bold(),
        },
        warn: LogFormatStyle {
            fg: Some(Color::Yellow),
            bg: None,
            style: Style::default(),
        },
        info: LogFormatStyle {
            fg: Some(Color::BrightCyan),
            bg: None,
            style: Style::default(),
        },
        debug: LogFormatStyle {
            fg: Some(Color::Magenta),
            bg: None,
            style: Style::default().bold(),
        },
        success: LogFormatStyle {
            fg: Some(Color::Green),
            bg: None,
            style: Style::default(),
        },
        critical: LogFormatStyle {
            fg: Some(Color::Black),
            bg: Some(Color::Cyan),
            style: Style::default().bold().underline(),
        },
    };

    let opts = LoggerOptions {
        truncate_previous_logs: true,
        custom_log_styles: Some(custom_log_styles),
        log_dir: None,
        no_console,
        ..Default::default()
    };

    Logger::init(None::<String>, opts).map_err(|e| crate::errors::DonutError::Io(e.to_string()))?;
    Ok(())
}


/// Debug logging helper.
///
/// On Windows uses `azathoth_logger` (when enabled). On Linux uses a direct `write` call.
#[inline(always)]
#[unsafe(link_section = ".text")]
pub fn log(_msg: &str) {
    #[cfg(target_os = "windows")]
    {
        #[cfg(feature = "logging")]
        {
            use azathoth_logger::Logger;
            LOG.log(_msg);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(feature = "logging")]
        {
            crate::platform::linux::logging::write_fd(1, _msg.as_bytes());
        }
    }
}

/// Error logging helper.
///
/// On Linux writes to `STDERR` via `write`. On Windows delegates to [`log`].
#[inline(always)]
#[unsafe(link_section = ".text")]
pub fn elog(_msg: &str) {
    #[cfg(target_os = "windows")]
    {
        log(_msg);
    }

    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(feature = "logging")]
        {
            crate::platform::linux::logging::write_fd(2, _msg.as_bytes());
        }
    }
}

/// Logging macro wrapper module to allow disabling logging at compile time.
pub mod logwrapper {
    /// Internal forwarding macro (do not use directly).
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __log_forward {
        ($name:ident, $($arg:tt)*) => {{
            #[cfg(feature = "logging")]
            { ::azathoth_logger::$name!($($arg)*); }

            #[cfg(not(feature = "logging"))]
            { }
        }};
    }

    /// Info-level log
    #[macro_export]
    macro_rules! info {
        ($($arg:tt)*) => { $crate::__log_forward!(info, $($arg)*); };
    }

    /// Error-level log
    #[macro_export]
    macro_rules! error {
        ($($arg:tt)*) => { $crate::__log_forward!(error, $($arg)*); };
    }

    /// Warning-level log
    #[macro_export]
    macro_rules! warn {
        ($($arg:tt)*) => { $crate::__log_forward!(warn, $($arg)*); };
    }

    /// Success-level log
    #[macro_export]
    macro_rules! success {
        ($($arg:tt)*) => { $crate::__log_forward!(success, $($arg)*); };
    }

    /// Critical-level log
    #[macro_export]
    macro_rules! critical {
        ($($arg:tt)*) => { $crate::__log_forward!(critical, $($arg)*); };
    }

    /// Debug-level log (compiled out in release by default).
    #[macro_export]
    macro_rules! debug {
        ($($arg:tt)*) => {{
            #[cfg(all(feature = "logging", debug_assertions))]
            { ::azathoth_logger::debug!($($arg)*); }

            #[cfg(not(all(feature = "logging", debug_assertions)))]
            { }
        }};
    }
}

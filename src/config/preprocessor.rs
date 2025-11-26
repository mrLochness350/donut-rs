use std::collections::HashMap;
use std::path::PathBuf;
use az_logger::error;
use serde_json::Value;
use crate::errors::{DonutError, DonutResult};

pub(crate) struct ConfigPreprocessor {
    replacements: HashMap<String, String>,
}

const CWD: &str = "{{cwd}}";
const HOME: &str = "{{home}}";
const OS: &str = "{{os}}";
const IP: &str = "{{ip}}";
impl ConfigPreprocessor {
    pub(crate) fn new() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("../../..")).to_string_lossy().to_string();
        let home = std::env::var("HOME").unwrap_or_else(|_| String::new());
        let mut replacements = HashMap::new();
        replacements.insert(CWD.to_string(), cwd);
        replacements.insert(HOME.to_string(), home);
        replacements.insert(OS.to_string(), std::env::consts::OS.to_string());
        replacements.insert(IP.to_string(), get_ip().unwrap_or_else(|_| "127.0.0.1".to_string()));
        Self { replacements }
    }

    fn process_value(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                for(k, v) in &self.replacements {
                    if s.contains(k) {
                        *s = s.replace(k,v);
                    }
                }
            }
            Value::Array(arr) => {
                for val in arr {
                    self.process_value(val);
                }
            }
            Value::Object(obj) => {
                for (_, v) in obj {
                    self.process_value(v);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn process_raw(&self, raw: &str, is_toml: bool) -> DonutResult<Value> {
        let mut value = if is_toml {
            let toml_val: toml::Value = toml::from_str(raw).map_err(|e| {
                error!("Failed too parse raw config: {e}");
                DonutError::SerializationError(e.to_string())
            })?;
            serde_json::to_value(toml_val).map_err(|e| {
                error!("Failed too convert toml::Value to serde_json::Value: {e}");
                DonutError::SerializationError(e.to_string())
            })?
        } else {
            serde_json::from_str(raw).map_err(|e| {
                error!("Failed too raw to serde_json::Value: {e}");
                DonutError::SerializationError(raw.to_string())
            })?
        };
        self.process_value(&mut value);
        Ok(value)
    }
}

fn get_ip() -> DonutResult<String> {
    Err(DonutError::ParseFailed)
}
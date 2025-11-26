use crate::instance::InstanceInformation;
use crate::prelude::{DonutConfig, FileInfo};

/// Actual Donut struct. Contains all the data necessary to create a payload
#[derive(Debug, Default)]
pub struct Donut {
    pub(crate) file_info: FileInfo,
    pub(crate) instance_information: InstanceInformation,
    pub(crate) config: DonutConfig,
    pub(crate) final_payload: Vec<u8>,
    pub(crate) http_payload: Option<Vec<u8>>,
}
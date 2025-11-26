use crate::prelude::InstanceMetadata;

/// Donut build result struct. Contains all the data necessary to save a payload
#[derive(Debug,  Default)]
pub struct DonutBuildResult {
    pub(crate) final_payload: Vec<u8>,
    pub(crate) compressed_instance: Vec<u8>,
    pub(crate) metadata: InstanceMetadata,
}

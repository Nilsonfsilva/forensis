//! Partition table support.

pub mod partition_table;
pub mod types;

pub mod gpt;
pub mod mbr;

pub use types::{Partition, PartitionType};

pub use partition_table::*;

pub use gpt::{Gpt, GptHeader};
pub use mbr::Mbr;

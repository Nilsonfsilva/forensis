#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    Unknown,
    Fat32,
    Ntfs,
    LinuxFilesystem,
    LinuxSwap,
    Extended,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub number: u32,
    pub start_sector: u64,
    pub sector_count: u64,
    pub partition_type: PartitionType,
}

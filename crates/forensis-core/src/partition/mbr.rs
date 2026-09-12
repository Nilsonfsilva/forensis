use crate::partition::{Partition, PartitionType};
use crate::result::Result;
use crate::traits::{PartitionTableReader, Readable};
use crate::types::ByteOffset;

pub struct Mbr {
    pub partitions: Vec<Partition>,
}

impl Mbr {
    pub fn parse<R: Readable>(reader: &mut R) -> Result<Self> {
        let mut sector = [0u8; 512];

        reader.read_at(ByteOffset::ZERO, &mut sector)?;

        let mut partitions = Vec::new();

        for index in 0..4 {
            let offset = 446 + (index * 16);

            let partition_type = Self::parse_partition_type(sector[offset + 4]);

            let start_lba = u32::from_le_bytes([
                sector[offset + 8],
                sector[offset + 9],
                sector[offset + 10],
                sector[offset + 11],
            ]);

            let sectors = u32::from_le_bytes([
                sector[offset + 12],
                sector[offset + 13],
                sector[offset + 14],
                sector[offset + 15],
            ]);

            if partition_type != PartitionType::Unknown {
                partitions.push(Partition {
                    number: (index + 1) as u32,
                    start_sector: start_lba as u64,
                    sector_count: sectors as u64,
                    partition_type,
                });
            }
        }

        Ok(Self { partitions })
    }

    pub fn parse_partition_type(value: u8) -> PartitionType {
        match value {
            0x07 => PartitionType::Ntfs,

            0x0B | 0x0C => PartitionType::Fat32,

            0x82 => PartitionType::LinuxSwap,

            0x83 => PartitionType::LinuxFilesystem,

            0x05 | 0x0F => PartitionType::Extended,

            _ => PartitionType::Unknown,
        }
    }
}

impl PartitionTableReader for Mbr {
    fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
}

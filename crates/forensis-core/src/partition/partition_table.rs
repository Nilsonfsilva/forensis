use crate::partition::{Gpt, Mbr, Partition, PartitionType};
use crate::result::Result;
use crate::traits::{PartitionTableReader, Readable};
use crate::types::ByteOffset;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableType {
    Mbr,
    Gpt,
    Unknown,
}

/// Represents a parsed partition table.
///
/// The enum hides the concrete partition table implementation
/// from consumers such as the CLI.
pub enum PartitionTable {
    Mbr(Mbr),
    Gpt(Gpt),
}

impl PartitionTable {
    /// Returns the partition table type.
    pub fn table_type(&self) -> PartitionTableType {
        match self {
            Self::Mbr(_) => PartitionTableType::Mbr,
            Self::Gpt(_) => PartitionTableType::Gpt,
        }
    }
}

impl PartitionTableReader for PartitionTable {
    fn partitions(&self) -> &[Partition] {
        match self {
            Self::Mbr(mbr) => mbr.partitions(),
            Self::Gpt(gpt) => gpt.partitions(),
        }
    }
}

pub struct PartitionTableDetector;

impl PartitionTableDetector {
    /// Detects the type of partition table.
    pub fn detect<R: Readable>(reader: &mut R) -> Result<PartitionTableType> {
        let mut sector = [0u8; 512];

        reader.read_at(ByteOffset::new(512), &mut sector)?;

        if &sector[0..8] == b"EFI PART" {
            return Ok(PartitionTableType::Gpt);
        }

        let mut mbr_sector = [0u8; 512];

        reader.read_at(ByteOffset::ZERO, &mut mbr_sector)?;

        let boot_signature = mbr_sector[510] == 0x55 && mbr_sector[511] == 0xAA;

        if !boot_signature {
            return Ok(PartitionTableType::Unknown);
        }

        /*
         * The 0x55AA signature alone is not enough
         * to identify an MBR.
         *
         * NTFS, FAT and other filesystem boot sectors
         * may also contain this signature.
         *
         * An MBR partition entry must contain a
         * partition type recognized by the MBR parser.
         */
        let has_partition = (0..4).any(|index| {
            let offset = 446 + index * 16;

            let partition_type = Mbr::parse_partition_type(mbr_sector[offset + 4]);

            let start_lba = u32::from_le_bytes([
                mbr_sector[offset + 8],
                mbr_sector[offset + 9],
                mbr_sector[offset + 10],
                mbr_sector[offset + 11],
            ]);

            let sector_count = u32::from_le_bytes([
                mbr_sector[offset + 12],
                mbr_sector[offset + 13],
                mbr_sector[offset + 14],
                mbr_sector[offset + 15],
            ]);

            partition_type != PartitionType::Unknown && start_lba != 0 && sector_count != 0
        });

        if has_partition {
            return Ok(PartitionTableType::Mbr);
        }

        Ok(PartitionTableType::Unknown)
    }

    /// Detects and parses the partition table.
    pub fn parse<R: Readable>(reader: &mut R) -> Result<Option<PartitionTable>> {
        let table_type = Self::detect(reader)?;

        match table_type {
            PartitionTableType::Mbr => {
                let mbr = Mbr::parse(reader)?;

                Ok(Some(PartitionTable::Mbr(mbr)))
            }

            PartitionTableType::Gpt => {
                let gpt = Gpt::parse(reader)?;

                Ok(Some(PartitionTable::Gpt(gpt)))
            }

            PartitionTableType::Unknown => Ok(None),
        }
    }
}

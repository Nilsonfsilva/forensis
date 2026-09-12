use crate::partition::{Partition, PartitionType};
use crate::result::Result;
use crate::traits::{PartitionTableReader, Readable};
use crate::types::ByteOffset;

#[derive(Debug, Clone)]
pub struct GptHeader {
    pub partition_entry_lba: u64,
    pub number_of_partition_entries: u32,
    pub size_of_partition_entry: u32,
}

pub struct Gpt {
    pub header: GptHeader,
    pub partitions: Vec<Partition>,
}

impl Gpt {
    /// Parses the GPT header and partition entries.
    pub fn parse<R: Readable>(reader: &mut R) -> Result<Self> {
        let mut sector = [0u8; 512];

        /*
         * ---------------------------------------------------------
         * GPT header is located at LBA 1.
         * ---------------------------------------------------------
         */

        reader.read_at(ByteOffset::new(512), &mut sector)?;

        /*
         * ---------------------------------------------------------
         * Validate GPT signature.
         * ---------------------------------------------------------
         */

        if &sector[0..8] != b"EFI PART" {
            return Ok(Self {
                header: GptHeader {
                    partition_entry_lba: 0,
                    number_of_partition_entries: 0,
                    size_of_partition_entry: 0,
                },

                partitions: Vec::new(),
            });
        }

        /*
         * ---------------------------------------------------------
         * Read GPT header fields.
         * ---------------------------------------------------------
         */

        let partition_entry_lba = u64::from_le_bytes(sector[72..80].try_into().unwrap());

        let number_of_partition_entries = u32::from_le_bytes(sector[80..84].try_into().unwrap());

        let size_of_partition_entry = u32::from_le_bytes(sector[84..88].try_into().unwrap());

        /*
         * ---------------------------------------------------------
         * Validate the partition-entry description.
         *
         * A valid GPT must provide:
         *
         *   - a non-zero partition-entry LBA
         *   - a non-zero number of entries
         *   - an entry size large enough to contain the
         *     mandatory GPT fields we read below
         *
         * GPT partition entries are normally 128 bytes.
         * ---------------------------------------------------------
         */

        if partition_entry_lba == 0
            || number_of_partition_entries == 0
            || size_of_partition_entry < 48
        {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Invalid GPT partition entry description".to_string(),
            ));
        }

        /*
         * Avoid allocating an unreasonable amount of memory
         * from a corrupted GPT header.
         */
        if size_of_partition_entry > 4096 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "GPT partition entry size is too large".to_string(),
            ));
        }

        if number_of_partition_entries > 1_000_000 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "GPT partition entry count is too large".to_string(),
            ));
        }

        let header = GptHeader {
            partition_entry_lba,
            number_of_partition_entries,
            size_of_partition_entry,
        };

        /*
         * ---------------------------------------------------------
         * Read partition entries.
         * ---------------------------------------------------------
         */

        let partitions = Self::read_partitions(reader, &header)?;

        Ok(Self { header, partitions })
    }

    fn read_partitions<R: Readable>(reader: &mut R, header: &GptHeader) -> Result<Vec<Partition>> {
        let mut partitions = Vec::new();

        let table_offset = header.partition_entry_lba.checked_mul(512).ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat(
                "GPT partition table offset overflow".to_string(),
            )
        })?;

        for index in 0..header.number_of_partition_entries {
            let entry_offset = (index as u64)
                .checked_mul(header.size_of_partition_entry as u64)
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "GPT partition entry offset overflow".to_string(),
                    )
                })?;

            let offset = table_offset.checked_add(entry_offset).ok_or_else(|| {
                crate::error::ForensisError::InvalidFormat(
                    "GPT partition entry offset overflow".to_string(),
                )
            })?;

            let entry_size = header.size_of_partition_entry as usize;

            let mut entry = vec![0u8; entry_size];

            reader.read_at(ByteOffset::new(offset), &mut entry)?;

            /*
             * -----------------------------------------------------
             * An empty GPT entry has a zero GUID.
             *
             * The first 16 bytes contain the partition type GUID.
             * -----------------------------------------------------
             */

            let first_byte = entry[0];

            if first_byte == 0 {
                continue;
            }

            /*
             * -----------------------------------------------------
             * Validate that the entry is large enough before
             * accessing the LBA fields.
             * -----------------------------------------------------
             */

            if entry.len() < 48 {
                return Err(crate::error::ForensisError::InvalidFormat(
                    "GPT partition entry is truncated".to_string(),
                ));
            }

            let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());

            let end_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());

            /*
             * -----------------------------------------------------
             * Validate the LBA range.
             * -----------------------------------------------------
             */

            if end_lba < start_lba {
                return Err(crate::error::ForensisError::InvalidFormat(
                    "GPT partition has invalid LBA range".to_string(),
                ));
            }

            let sector_count = end_lba
                .checked_sub(start_lba)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "GPT partition sector count overflow".to_string(),
                    )
                })?;

            partitions.push(Partition {
                number: index + 1,
                start_sector: start_lba,
                sector_count,
                partition_type: PartitionType::Unknown,
            });
        }

        Ok(partitions)
    }
}

impl PartitionTableReader for Gpt {
    fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
}

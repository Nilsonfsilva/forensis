use crate::error::ForensisError;
use crate::result::Result;

use super::data_run::DataRun;

/// NTFS $DATA attribute type.
pub const DATA_ATTRIBUTE_TYPE: u32 = 0x80;

/// Represents NTFS data attribute.
#[derive(Debug, Clone)]
pub struct DataAttribute {
    /// Indicates if the attribute is non-resident.
    pub non_resident: bool,

    /// Real file size.
    pub real_size: u64,

    /// Allocated size on disk.
    pub allocated_size: u64,

    /// Resident data content.
    pub resident_data: Option<Vec<u8>>,

    /// Data runs of a non-resident attribute.
    pub data_runs: Vec<DataRun>,
}

impl DataAttribute {
    /// Parses a $DATA attribute.
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < 16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid DATA attribute".to_string(),
            ));
        }

        let attribute_type = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

        if attribute_type != DATA_ATTRIBUTE_TYPE {
            return Err(ForensisError::InvalidFormat(
                "Not a DATA attribute".to_string(),
            ));
        }

        let length = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;

        if length > buffer.len() {
            return Err(ForensisError::InvalidFormat(
                "Truncated DATA attribute".to_string(),
            ));
        }

        let non_resident = buffer[8] != 0;

        /*
         * ---------------------------------------------------------
         * RESIDENT DATA
         * ---------------------------------------------------------
         */

        if !non_resident {
            if length < 22 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid resident DATA attribute".to_string(),
                ));
            }

            let value_length =
                u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]) as usize;

            let value_offset = u16::from_le_bytes([buffer[20], buffer[21]]) as usize;

            let value_end = value_offset.checked_add(value_length).ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid DATA value range".to_string())
            })?;

            if value_offset < 22 || value_end > length {
                return Err(ForensisError::InvalidFormat(
                    "DATA value exceeds attribute".to_string(),
                ));
            }

            let data = buffer[value_offset..value_end].to_vec();

            return Ok(Self {
                non_resident: false,
                real_size: value_length as u64,
                allocated_size: value_length as u64,
                resident_data: Some(data),
                data_runs: Vec::new(),
            });
        }

        /*
         * ---------------------------------------------------------
         * NON-RESIDENT DATA
         * ---------------------------------------------------------
         *
         * NTFS non-resident attribute layout:
         *
         * 32: Data runlist offset
         * 40: Allocated size
         * 48: Real size
         */

        if length < 64 {
            return Err(ForensisError::InvalidFormat(
                "Invalid non-resident DATA attribute".to_string(),
            ));
        }

        let runlist_offset = u16::from_le_bytes([buffer[32], buffer[33]]) as usize;

        let allocated_size = u64::from_le_bytes([
            buffer[40], buffer[41], buffer[42], buffer[43], buffer[44], buffer[45], buffer[46],
            buffer[47],
        ]);

        let real_size = u64::from_le_bytes([
            buffer[48], buffer[49], buffer[50], buffer[51], buffer[52], buffer[53], buffer[54],
            buffer[55],
        ]);

        if runlist_offset >= length {
            return Err(ForensisError::InvalidFormat(
                "Invalid DATA runlist offset".to_string(),
            ));
        }

        let data_runs = DataRun::parse(&buffer[runlist_offset..length])?;

        Ok(Self {
            non_resident: true,
            real_size,
            allocated_size,
            resident_data: None,
            data_runs,
        })
    }
}

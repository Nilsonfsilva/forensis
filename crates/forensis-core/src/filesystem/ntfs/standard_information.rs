//! NTFS $STANDARD_INFORMATION attribute parser.
//!
//! This module parses the contents of the NTFS
//! $STANDARD_INFORMATION attribute, which stores
//! timestamps and file metadata.

use crate::error::ForensisError;
use crate::result::Result;

/// Parsed NTFS $STANDARD_INFORMATION attribute.
#[derive(Debug, Clone)]
pub struct StandardInformation {
    /// File creation timestamp (Windows FILETIME).
    pub creation_time: u64,

    /// File modification timestamp (Windows FILETIME).
    pub modification_time: u64,

    /// MFT record modification timestamp.
    pub mft_modification_time: u64,

    /// Last access timestamp.
    pub access_time: u64,

    /// NTFS file attributes.
    pub file_attributes: u32,
}

impl StandardInformation {
    /// Parses a $STANDARD_INFORMATION attribute.
    ///
    /// The parser currently supports the common
    /// 48-byte version of the structure.
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < 36 {
            return Err(ForensisError::InvalidFormat(
                "Invalid $STANDARD_INFORMATION attribute".to_string(),
            ));
        }

        Ok(Self {
            creation_time: u64::from_le_bytes([
                buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                buffer[7],
            ]),

            modification_time: u64::from_le_bytes([
                buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
                buffer[15],
            ]),

            mft_modification_time: u64::from_le_bytes([
                buffer[16], buffer[17], buffer[18], buffer[19], buffer[20], buffer[21], buffer[22],
                buffer[23],
            ]),

            access_time: u64::from_le_bytes([
                buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30],
                buffer[31],
            ]),

            file_attributes: u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]),
        })
    }
}

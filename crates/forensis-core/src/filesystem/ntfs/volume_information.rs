use crate::error::ForensisError;
use crate::result::Result;

/// Represents the NTFS $VOLUME_INFORMATION attribute.
#[derive(Debug, Clone)]
pub struct VolumeInformation {
    major_version: u8,
    minor_version: u8,
    flags: u16,
}

impl VolumeInformation {
    /// Parses a resident $VOLUME_INFORMATION attribute.
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Resident header (24 bytes)
        // Payload starts after it.
        if data.len() < 32 {
            return Err(ForensisError::InvalidFormat(
                "Invalid $VOLUME_INFORMATION attribute".to_string(),
            ));
        }

        let offset = 24;

        let major_version = data[offset + 8];
        let minor_version = data[offset + 9];

        let flags = u16::from_le_bytes([data[offset + 10], data[offset + 11]]);

        Ok(Self {
            major_version,
            minor_version,
            flags,
        })
    }

    /// NTFS major version.
    pub fn major_version(&self) -> u8 {
        self.major_version
    }

    /// NTFS minor version.
    pub fn minor_version(&self) -> u8 {
        self.minor_version
    }

    /// Raw volume flags.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Returns true if the volume is marked dirty.
    pub fn is_dirty(&self) -> bool {
        self.flags & 0x0001 != 0
    }
}

use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 extent.
///
/// An extent represents a contiguous range of filesystem
/// blocks belonging to a file.
#[derive(Debug, Clone)]
pub struct Ext4Extent {
    logical_block: u32,
    physical_block: u64,
    length: u16,
    initialized: bool,
}

impl Ext4Extent {
    /// Size of an EXT4 extent structure.
    pub const SIZE: usize = 12;

    /// Parses an extent from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 extent".to_string(),
            ));
        }

        let logical_block = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let raw_length = u16::from_le_bytes([data[4], data[5]]);

        let physical_low = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        let physical_high = u16::from_le_bytes([data[6], data[7]]);

        let initialized = (raw_length & 0x8000) == 0;

        let length = raw_length & 0x7FFF;

        let physical_block = ((physical_high as u64) << 32) | physical_low as u64;

        Ok(Self {
            logical_block,
            physical_block,
            length,
            initialized,
        })
    }

    /// Returns the first logical block covered by this extent.
    pub fn logical_block(&self) -> u32 {
        self.logical_block
    }

    /// Returns the first physical block occupied by this extent.
    pub fn physical_block(&self) -> u64 {
        self.physical_block
    }

    /// Returns the number of blocks in this extent.
    pub fn length(&self) -> u16 {
        self.length
    }

    /// Returns true when the extent contains initialized data.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the last logical block covered by this extent.
    pub fn last_logical_block(&self) -> u32 {
        self.logical_block
            .saturating_add(self.length as u32)
            .saturating_sub(1)
    }

    /// Returns the last physical block occupied by this extent.
    pub fn last_physical_block(&self) -> u64 {
        self.physical_block
            .saturating_add(self.length as u64)
            .saturating_sub(1)
    }
}

use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 extent tree index entry.
///
/// An index entry belongs to an internal extent tree node.
/// It points to another extent tree block containing either
/// more index entries or leaf extents.
#[derive(Debug, Clone)]
pub struct Ext4ExtentIndex {
    logical_block: u32,
    leaf_block: u64,
}

impl Ext4ExtentIndex {
    /// Size of an EXT4 extent index entry.
    pub const SIZE: usize = 12;

    /// Parses an EXT4 extent index entry from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 extent index: insufficient data".to_string(),
            ));
        }

        let logical_block = u32::from_le_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]);

        let leaf_low = u32::from_le_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]);

        let leaf_high = u16::from_le_bytes([data[0x08], data[0x09]]);

        let leaf_block = ((leaf_high as u64) << 32) | leaf_low as u64;

        Ok(Self {
            logical_block,
            leaf_block,
        })
    }

    /// Returns the first logical filesystem block covered
    /// by the child node referenced by this index.
    pub fn logical_block(&self) -> u32 {
        self.logical_block
    }

    /// Returns the physical filesystem block containing
    /// the child extent tree node.
    pub fn leaf_block(&self) -> u64 {
        self.leaf_block
    }
}

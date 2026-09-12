use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 block bitmap.
///
/// Each bit represents one filesystem block.
///
/// 1 = block allocated
/// 0 = block free
#[derive(Debug, Clone)]
pub struct Ext4BlockBitmap {
    data: Vec<u8>,
}

impl Ext4BlockBitmap {
    /// Creates a block bitmap from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty EXT4 block bitmap".to_string(),
            ));
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns true if a block is allocated.
    ///
    /// The block number is zero-based within the bitmap.
    pub fn is_allocated(&self, block: u64) -> bool {
        let byte_index = (block / 8) as usize;

        if byte_index >= self.data.len() {
            return false;
        }

        let bit_index = (block % 8) as u8;

        (self.data[byte_index] & (1u8 << bit_index)) != 0
    }

    /// Returns true if a block is free.
    pub fn is_free(&self, block: u64) -> bool {
        !self.is_allocated(block)
    }

    /// Returns the number of blocks represented by this bitmap.
    pub fn block_count(&self) -> u64 {
        (self.data.len() * 8) as u64
    }

    /// Returns the raw bitmap.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }
}

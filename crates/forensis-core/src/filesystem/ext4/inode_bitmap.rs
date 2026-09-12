use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 inode bitmap.
///
/// Each bit represents one inode.
///
/// Bit value:
/// - 1 = inode allocated
/// - 0 = inode free
///
/// EXT4 inode numbers are one-based. Therefore:
///
/// bitmap bit 0 -> inode 1
/// bitmap bit 1 -> inode 2
/// bitmap bit 2 -> inode 3
/// ...
#[derive(Debug, Clone)]
pub struct Ext4InodeBitmap {
    data: Vec<u8>,
}

impl Ext4InodeBitmap {
    /// Creates an inode bitmap from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty EXT4 inode bitmap".to_string(),
            ));
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns true if the specified inode is allocated.
    ///
    /// EXT4 inode numbers start at 1.
    pub fn is_allocated(&self, inode: u64) -> bool {
        if inode == 0 {
            return false;
        }

        let index = inode - 1;
        let byte = (index / 8) as usize;

        if byte >= self.data.len() {
            return false;
        }

        let bit = (index % 8) as u8;

        self.data[byte] & (1u8 << bit) != 0
    }

    /// Returns true if the specified inode is free.
    pub fn is_free(&self, inode: u64) -> bool {
        !self.is_allocated(inode)
    }

    /// Returns the number of bits represented by this bitmap.
    ///
    /// Each bit represents one inode.
    pub fn inode_count(&self) -> u64 {
        (self.data.len() * 8) as u64
    }

    /// Returns the number of allocated inodes represented
    /// by this bitmap.
    pub fn allocated_count(&self) -> u64 {
        self.data.iter().map(|byte| byte.count_ones() as u64).sum()
    }

    /// Returns the number of free inode positions represented
    /// by this bitmap.
    pub fn free_count(&self) -> u64 {
        self.inode_count() - self.allocated_count()
    }

    /// Returns the raw bitmap.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns the size of the bitmap in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 block group descriptor.
///
/// Describes where the allocation metadata for a block group
/// is located.
#[derive(Debug, Clone)]
pub struct Ext4BlockGroup {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    free_blocks_count: u16,
    free_inodes_count: u16,
    used_dirs_count: u16,
}

impl Ext4BlockGroup {
    /// Size of a classic EXT4 block group descriptor.
    pub const SIZE: usize = 32;

    /// Parses a block group descriptor.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block group descriptor".to_string(),
            ));
        }

        let block_bitmap = u32::from_le_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]);

        let inode_bitmap = u32::from_le_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]);

        let inode_table = u32::from_le_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]);

        let free_blocks_count = u16::from_le_bytes([data[0x0C], data[0x0D]]);

        let free_inodes_count = u16::from_le_bytes([data[0x0E], data[0x0F]]);

        let used_dirs_count = u16::from_le_bytes([data[0x10], data[0x11]]);

        Ok(Self {
            block_bitmap,
            inode_bitmap,
            inode_table,
            free_blocks_count,
            free_inodes_count,
            used_dirs_count,
        })
    }

    /// Returns the block containing the block bitmap.
    pub fn block_bitmap(&self) -> u32 {
        self.block_bitmap
    }

    /// Returns the block containing the inode bitmap.
    pub fn inode_bitmap(&self) -> u32 {
        self.inode_bitmap
    }

    /// Returns the first block of the inode table.
    pub fn inode_table(&self) -> u32 {
        self.inode_table
    }

    /// Returns the number of free blocks.
    pub fn free_blocks_count(&self) -> u16 {
        self.free_blocks_count
    }

    /// Returns the number of free inodes.
    pub fn free_inodes_count(&self) -> u16 {
        self.free_inodes_count
    }

    /// Returns the number of directories in this group.
    pub fn used_dirs_count(&self) -> u16 {
        self.used_dirs_count
    }
}

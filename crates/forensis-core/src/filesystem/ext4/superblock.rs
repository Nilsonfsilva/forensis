use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 Superblock.
///
/// The superblock contains the fundamental information required
/// to interpret an EXT4 filesystem.
#[derive(Debug, Clone)]
pub struct Ext4Superblock {
    inodes_count: u32,
    blocks_count_lo: u32,
    free_blocks_count_lo: u32,
    free_inodes_count: u32,
    first_data_block: u32,
    log_block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    magic: u16,
}

impl Ext4Superblock {
    /// Size of the EXT4 superblock structure.
    pub const SIZE: usize = 1024;

    /// Offset of the EXT4 magic field.
    const MAGIC_OFFSET: usize = 0x38;

    /// Offset of the inode size field.
    const INODE_SIZE_OFFSET: usize = 0x58;

    /// EXT4 magic value.
    pub const EXT4_MAGIC: u16 = 0xEF53;

    /// Parses an EXT4 superblock from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 superblock: insufficient data".to_string(),
            ));
        }

        let magic = u16::from_le_bytes([data[Self::MAGIC_OFFSET], data[Self::MAGIC_OFFSET + 1]]);

        if magic != Self::EXT4_MAGIC {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 superblock magic".to_string(),
            ));
        }

        let inodes_count = u32::from_le_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]);

        let blocks_count_lo = u32::from_le_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]);

        let free_blocks_count_lo =
            u32::from_le_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]);

        let free_inodes_count =
            u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);

        let first_data_block = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);

        let log_block_size = u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]);

        let blocks_per_group = u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]);

        let inodes_per_group = u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]);

        let inode_size = u16::from_le_bytes([
            data[Self::INODE_SIZE_OFFSET],
            data[Self::INODE_SIZE_OFFSET + 1],
        ]);

        if inode_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inode size".to_string(),
            ));
        }

        Ok(Self {
            inodes_count,
            blocks_count_lo,
            free_blocks_count_lo,
            free_inodes_count,
            first_data_block,
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            magic,
        })
    }

    /// Returns the filesystem magic value.
    pub fn magic(&self) -> u16 {
        self.magic
    }

    /// Returns the total number of inodes.
    pub fn inodes_count(&self) -> u32 {
        self.inodes_count
    }

    /// Returns the total number of low 32-bit blocks.
    pub fn blocks_count(&self) -> u32 {
        self.blocks_count_lo
    }

    /// Returns the number of free blocks.
    pub fn free_blocks_count(&self) -> u32 {
        self.free_blocks_count_lo
    }

    /// Returns the number of free inodes.
    pub fn free_inodes_count(&self) -> u32 {
        self.free_inodes_count
    }

    /// Returns the first data block.
    pub fn first_data_block(&self) -> u32 {
        self.first_data_block
    }

    /// Returns the filesystem block size.
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }

    /// Returns the number of blocks per group.
    pub fn blocks_per_group(&self) -> u32 {
        self.blocks_per_group
    }

    /// Returns the number of inodes per group.
    pub fn inodes_per_group(&self) -> u32 {
        self.inodes_per_group
    }

    /// Returns the size of an inode in bytes.
    pub fn inode_size(&self) -> u16 {
        self.inode_size
    }
}

use crate::error::ForensisError;
use crate::result::Result;

use super::block_group_descriptor::Ext4BlockGroupDescriptor;
use super::superblock::Ext4Superblock;

/// Locates an inode inside an EXT4 filesystem.
///
/// EXT4 organizes inodes into block groups.
///
/// Each block group contains an inode table, and the group
/// descriptor tells us where that inode table begins.
///
/// This module converts an inode number into its physical
/// location inside the inode table.
///
/// The locator does not read the inode itself.
/// It only calculates where the inode is located.
#[derive(Debug, Clone)]
pub struct Ext4InodeLocator {
    superblock: Ext4Superblock,
    inode_size: u32,
}

impl Ext4InodeLocator {
    /// Creates an inode locator.
    ///
    /// The inode size is normally obtained from the EXT4
    /// superblock.
    pub fn new(superblock: Ext4Superblock, inode_size: u32) -> Result<Self> {
        if inode_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inode size".to_string(),
            ));
        }

        if !inode_size.is_power_of_two() {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode size must be a power of two".to_string(),
            ));
        }

        if inode_size < 128 {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode size is smaller than the minimum".to_string(),
            ));
        }

        Ok(Self {
            superblock,
            inode_size,
        })
    }

    /// Returns the configured inode size.
    pub fn inode_size(&self) -> u32 {
        self.inode_size
    }

    /// Returns the block group containing the inode.
    ///
    /// EXT4 inode numbering starts at 1.
    ///
    /// For example, with 8192 inodes per group:
    ///
    /// - inode 1 belongs to group 0
    /// - inode 8192 belongs to group 0
    /// - inode 8193 belongs to group 1
    pub fn group_for_inode(&self, inode_number: u32) -> Result<u32> {
        if inode_number == 0 {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode number cannot be zero".to_string(),
            ));
        }

        let inodes_per_group = self.superblock.inodes_per_group();

        if inodes_per_group == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inodes per group".to_string(),
            ));
        }

        Ok((inode_number - 1) / inodes_per_group)
    }

    /// Returns the zero-based inode index inside
    /// its block group.
    pub fn index_in_group(&self, inode_number: u32) -> Result<u32> {
        if inode_number == 0 {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode number cannot be zero".to_string(),
            ));
        }

        let inodes_per_group = self.superblock.inodes_per_group();

        if inodes_per_group == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inodes per group".to_string(),
            ));
        }

        Ok((inode_number - 1) % inodes_per_group)
    }

    /// Calculates the byte offset of an inode
    /// inside the inode table.
    ///
    /// `inode_table_block` is the first filesystem block
    /// containing the inode table for the corresponding
    /// block group.
    pub fn inode_offset(&self, inode_number: u32, inode_table_block: u64) -> Result<u64> {
        let index = self.index_in_group(inode_number)? as u64;

        let block_size = self.superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        let inode_byte_offset = index.checked_mul(self.inode_size as u64).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 inode offset overflow".to_string())
        })?;

        let table_offset = inode_table_block.checked_mul(block_size).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 inode table offset overflow".to_string())
        })?;

        table_offset
            .checked_add(inode_byte_offset)
            .ok_or_else(|| ForensisError::InvalidFormat("EXT4 inode offset overflow".to_string()))
    }

    /// Calculates the filesystem block containing
    /// an inode.
    pub fn inode_block(&self, inode_number: u32, inode_table_block: u64) -> Result<u64> {
        let offset = self.inode_offset(inode_number, inode_table_block)?;

        let block_size = self.superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        Ok(offset / block_size)
    }

    /// Returns the byte offset of an inode inside
    /// its containing filesystem block.
    pub fn offset_inside_block(&self, inode_number: u32) -> Result<u64> {
        let index = self.index_in_group(inode_number)? as u64;

        let block_size = self.superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        let offset = index.checked_mul(self.inode_size as u64).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 inode offset overflow".to_string())
        })?;

        Ok(offset % block_size)
    }

    /// Calculates the complete physical location
    /// of an inode.
    ///
    /// The returned tuple contains:
    ///
    /// - block group
    /// - inode index inside the group
    /// - byte offset inside the filesystem
    ///
    /// The descriptor is required because the inode table
    /// location belongs to the block group descriptor.
    pub fn locate(
        &self,
        inode_number: u32,
        descriptor: &Ext4BlockGroupDescriptor,
    ) -> Result<(u32, u32, u64)> {
        let group = self.group_for_inode(inode_number)?;

        let index = self.index_in_group(inode_number)?;

        let inode_table_block = descriptor.inode_table();

        let offset = self.inode_offset(inode_number, inode_table_block)?;

        Ok((group, index, offset))
    }
}

use crate::error::ForensisError;
use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

use super::{
    Ext4BlockBitmap, Ext4BlockGroupDescriptor, Ext4BlockGroupTable, Ext4InodeBitmap,
    Ext4InodeTable, Ext4Superblock,
};

/// Reader for an EXT4 filesystem.
///
/// Ext4Reader provides low-level access to the main EXT4
/// filesystem metadata structures.
pub struct Ext4Reader<R> {
    reader: R,
    partition_offset: u64,
}

impl<R: Readable> Ext4Reader<R> {
    /// Creates a new EXT4 reader.
    ///
    /// `partition_offset` is the absolute byte offset where
    /// the EXT4 filesystem starts inside the underlying image
    /// or device.
    pub fn new(reader: R, partition_offset: u64) -> Self {
        Self {
            reader,
            partition_offset,
        }
    }

    /// Returns the filesystem partition offset.
    pub fn partition_offset(&self) -> u64 {
        self.partition_offset
    }

    /// Reads bytes from a filesystem-relative offset.
    ///
    /// The offset is relative to the beginning of the EXT4
    /// filesystem. The partition offset is added internally
    /// before accessing the underlying evidence source.
    pub fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let absolute_offset = self
            .partition_offset
            .checked_add(offset)
            .ok_or_else(|| ForensisError::InvalidFormat("EXT4 read offset overflow".to_string()))?;

        self.reader
            .read_at(ByteOffset::new(absolute_offset), buffer)
    }

    /// Reads the EXT4 superblock.
    ///
    /// The superblock starts 1024 bytes after the
    /// beginning of the filesystem.
    pub fn read_superblock(&mut self) -> Result<Ext4Superblock> {
        let offset = self.partition_offset.checked_add(1024).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 superblock offset overflow".to_string())
        })?;

        let mut data = [0u8; Ext4Superblock::SIZE];

        self.reader.read_at(ByteOffset::new(offset), &mut data)?;

        Ext4Superblock::parse(&data)
    }

    /// Reads the EXT4 block group descriptor table.
    pub fn read_block_groups(
        &mut self,
        superblock: &Ext4Superblock,
    ) -> Result<Ext4BlockGroupTable> {
        let block_size = superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        let blocks_per_group = superblock.blocks_per_group() as u64;

        if blocks_per_group == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 blocks per group".to_string(),
            ));
        }

        let total_blocks = superblock.blocks_count() as u64;
        let first_data_block = superblock.first_data_block() as u64;

        if total_blocks <= first_data_block {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block count".to_string(),
            ));
        }

        let usable_blocks = total_blocks - first_data_block;
        let group_count = usable_blocks.div_ceil(blocks_per_group);

        if group_count == 0 {
            return Err(ForensisError::InvalidFormat(
                "EXT4 filesystem has no block groups".to_string(),
            ));
        }

        let descriptor_size = Ext4BlockGroupDescriptor::SIZE as u64;

        let table_size = group_count.checked_mul(descriptor_size).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block group table size overflow".to_string())
        })?;

        let descriptor_block = if block_size == 1024 { 2u64 } else { 1u64 };

        let table_relative_offset = descriptor_block.checked_mul(block_size).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block group table offset overflow".to_string())
        })?;

        let table_offset = self
            .partition_offset
            .checked_add(table_relative_offset)
            .ok_or_else(|| {
                ForensisError::InvalidFormat("EXT4 block group table offset overflow".to_string())
            })?;

        let table_size_usize = usize::try_from(table_size).map_err(|_| {
            ForensisError::InvalidFormat("EXT4 block group table is too large".to_string())
        })?;

        let mut data = vec![0u8; table_size_usize];

        self.reader
            .read_at(ByteOffset::new(table_offset), &mut data)?;

        Ext4BlockGroupTable::parse(&data)
    }

    /// Reads the block bitmap of a block group.
    pub fn read_block_bitmap(
        &mut self,
        superblock: &Ext4Superblock,
        descriptor: &Ext4BlockGroupDescriptor,
    ) -> Result<Ext4BlockBitmap> {
        let data = self.read_block(superblock, descriptor.block_bitmap())?;

        Ext4BlockBitmap::parse(&data)
    }

    /// Reads the inode bitmap of a block group.
    pub fn read_inode_bitmap(
        &mut self,
        superblock: &Ext4Superblock,
        descriptor: &Ext4BlockGroupDescriptor,
    ) -> Result<Ext4InodeBitmap> {
        let data = self.read_block(superblock, descriptor.inode_bitmap())?;

        Ext4InodeBitmap::parse(&data)
    }

    /// Reads the inode table of a block group.
    ///
    /// The size of the inode table is calculated from:
    ///
    /// inodes_per_group * inode_size
    ///
    /// rounded up to complete filesystem blocks.
    pub fn read_inode_table(
        &mut self,
        superblock: &Ext4Superblock,
        descriptor: &Ext4BlockGroupDescriptor,
    ) -> Result<Ext4InodeTable> {
        let block_size = superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        let inode_size = superblock.inode_size() as u64;

        if inode_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inode size".to_string(),
            ));
        }

        let inodes_per_group = superblock.inodes_per_group() as u64;

        if inodes_per_group == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inodes per group".to_string(),
            ));
        }

        let inode_table_bytes = inodes_per_group.checked_mul(inode_size).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 inode table size overflow".to_string())
        })?;

        let inode_table_blocks = inode_table_bytes.div_ceil(block_size);

        let total_bytes = inode_table_blocks.checked_mul(block_size).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 inode table size overflow".to_string())
        })?;

        let offset = self.block_offset(superblock, descriptor.inode_table())?;

        let size = usize::try_from(total_bytes).map_err(|_| {
            ForensisError::InvalidFormat("EXT4 inode table is too large".to_string())
        })?;

        let mut data = vec![0u8; size];

        self.reader.read_at(ByteOffset::new(offset), &mut data)?;

        Ext4InodeTable::parse(&data, superblock.inode_size())
    }

    /// Reads all metadata associated with one block group.
    ///
    /// Returns:
    ///
    /// - block bitmap
    /// - inode bitmap
    /// - inode table
    pub fn read_block_group(
        &mut self,
        superblock: &Ext4Superblock,
        descriptor: &Ext4BlockGroupDescriptor,
    ) -> Result<(Ext4BlockBitmap, Ext4InodeBitmap, Ext4InodeTable)> {
        let block_bitmap = self.read_block_bitmap(superblock, descriptor)?;
        let inode_bitmap = self.read_inode_bitmap(superblock, descriptor)?;
        let inode_table = self.read_inode_table(superblock, descriptor)?;

        Ok((block_bitmap, inode_bitmap, inode_table))
    }

    /// Reads the superblock and block group table.
    pub fn read_metadata(&mut self) -> Result<(Ext4Superblock, Ext4BlockGroupTable)> {
        let superblock = self.read_superblock()?;
        let block_groups = self.read_block_groups(&superblock)?;

        Ok((superblock, block_groups))
    }

    /// Converts an EXT4 filesystem block number
    /// into an absolute byte offset.
    fn block_offset(&self, superblock: &Ext4Superblock, block: u64) -> Result<u64> {
        let block_size = superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        let relative_offset = block.checked_mul(block_size).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block offset overflow".to_string())
        })?;

        self.partition_offset
            .checked_add(relative_offset)
            .ok_or_else(|| ForensisError::InvalidFormat("EXT4 block offset overflow".to_string()))
    }

    /// Reads exactly one filesystem block at the given block number.
    ///
    /// This is used to access directory blocks, file data blocks
    /// and external extent tree index blocks during the
    /// investigation walk.
    pub fn read_block(&mut self, superblock: &Ext4Superblock, block: u64) -> Result<Vec<u8>> {
        let block_size = superblock.block_size() as u64;

        if block_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block size".to_string(),
            ));
        }

        let size = usize::try_from(block_size).map_err(|_| {
            ForensisError::InvalidFormat("EXT4 block size is too large".to_string())
        })?;

        let offset = self.block_offset(superblock, block)?;

        let mut data = vec![0u8; size];

        self.reader.read_at(ByteOffset::new(offset), &mut data)?;

        Ok(data)
    }
}

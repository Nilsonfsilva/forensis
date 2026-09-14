use crate::error::ForensisError;
use crate::result::Result;
use crate::traits::Readable;

use super::{
    investigate_filesystem, investigate_filesystem_with_progress, Ext4BlockBitmap,
    Ext4BlockGroupDescriptor, Ext4BlockGroupTable, Ext4Inode, Ext4InodeBitmap, Ext4InodeLocator,
    Ext4InodeTable, Ext4Investigation, Ext4Reader, Ext4Superblock,
};

/// Represents an EXT4 filesystem.
///
/// This structure provides the top-level representation
/// of an EXT4 volume and connects its main metadata
/// structures.
#[derive(Debug, Clone)]
pub struct Ext4Filesystem {
    superblock: Ext4Superblock,
    block_groups: Ext4BlockGroupTable,
}

impl Ext4Filesystem {
    /// Creates an EXT4 filesystem representation.
    pub fn new(superblock: Ext4Superblock, block_groups: Ext4BlockGroupTable) -> Result<Self> {
        if block_groups.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "EXT4 filesystem has no block groups".to_string(),
            ));
        }

        Ok(Self {
            superblock,
            block_groups,
        })
    }

    /// Opens an EXT4 filesystem using an existing reader.
    ///
    /// The reader is consumed while the filesystem metadata
    /// is loaded. The resulting filesystem contains the
    /// parsed superblock and block group descriptor table.
    pub fn open<R: Readable>(reader: &mut Ext4Reader<R>) -> Result<Self> {
        let (superblock, block_groups) = reader.read_metadata()?;

        Self::new(superblock, block_groups)
    }

    /// Returns the EXT4 superblock.
    pub fn superblock(&self) -> &Ext4Superblock {
        &self.superblock
    }

    /// Returns the EXT4 block group descriptor table.
    pub fn block_groups(&self) -> &Ext4BlockGroupTable {
        &self.block_groups
    }

    /// Returns a block group descriptor.
    pub fn block_group(&self, index: usize) -> Option<&Ext4BlockGroupDescriptor> {
        self.block_groups.get(index)
    }

    /// Returns the filesystem block size.
    pub fn block_size(&self) -> u32 {
        self.superblock.block_size()
    }

    /// Returns the total number of inodes.
    pub fn inode_count(&self) -> u32 {
        self.superblock.inodes_count()
    }

    /// Returns the total number of blocks.
    pub fn block_count(&self) -> u32 {
        self.superblock.blocks_count()
    }

    /// Returns the number of free blocks.
    pub fn free_block_count(&self) -> u32 {
        self.superblock.free_blocks_count()
    }

    /// Returns the number of free inodes.
    pub fn free_inode_count(&self) -> u32 {
        self.superblock.free_inodes_count()
    }

    /// Returns the number of block groups.
    pub fn block_group_count(&self) -> usize {
        self.block_groups.len()
    }

    /// Locates an inode inside the EXT4 filesystem.
    ///
    /// Returns:
    ///
    /// - block group containing the inode
    /// - zero-based inode index inside the group
    /// - byte offset of the inode inside the filesystem
    pub fn locate_inode(&self, inode_number: u32) -> Result<(u32, u32, u64)> {
        if inode_number == 0 {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode number cannot be zero".to_string(),
            ));
        }

        if inode_number > self.superblock.inodes_count() {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode number is outside the filesystem".to_string(),
            ));
        }

        let locator =
            Ext4InodeLocator::new(self.superblock.clone(), self.superblock.inode_size() as u32)?;

        let group = locator.group_for_inode(inode_number)?;

        let descriptor = self.block_group(group as usize).ok_or_else(|| {
            ForensisError::InvalidFormat(
                "EXT4 inode block group is outside the filesystem".to_string(),
            )
        })?;

        locator.locate(inode_number, descriptor)
    }

    /// Reads one inode from the EXT4 filesystem.
    ///
    /// The inode number is first translated into a filesystem-relative
    /// byte offset. The reader then accesses exactly one inode and
    /// parses its bytes into an `Ext4Inode`.
    pub fn read_inode<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
        inode_number: u32,
    ) -> Result<Ext4Inode> {
        let (_, _, offset) = self.locate_inode(inode_number)?;

        let inode_size = usize::from(self.superblock.inode_size());

        if inode_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inode size".to_string(),
            ));
        }

        let mut data = vec![0u8; inode_size];

        reader.read_at(offset, &mut data)?;

        Ext4Inode::parse(&data)
    }

    /// Reads the block bitmap for a block group.
    pub fn read_block_bitmap<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
        group: usize,
    ) -> Result<Ext4BlockBitmap> {
        let descriptor = self.block_group(group).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block group index out of bounds".to_string())
        })?;

        reader.read_block_bitmap(&self.superblock, descriptor)
    }

    /// Reads the inode bitmap for a block group.
    pub fn read_inode_bitmap<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
        group: usize,
    ) -> Result<Ext4InodeBitmap> {
        let descriptor = self.block_group(group).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block group index out of bounds".to_string())
        })?;

        reader.read_inode_bitmap(&self.superblock, descriptor)
    }

    /// Reads the inode table for a block group.
    pub fn read_inode_table<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
        group: usize,
    ) -> Result<Ext4InodeTable> {
        let descriptor = self.block_group(group).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block group index out of bounds".to_string())
        })?;

        reader.read_inode_table(&self.superblock, descriptor)
    }

    /// Reads all metadata associated with a block group.
    pub fn read_block_group<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
        group: usize,
    ) -> Result<(Ext4BlockBitmap, Ext4InodeBitmap, Ext4InodeTable)> {
        let descriptor = self.block_group(group).ok_or_else(|| {
            ForensisError::InvalidFormat("EXT4 block group index out of bounds".to_string())
        })?;

        reader.read_block_group(&self.superblock, descriptor)
    }

    /// Investigates the EXT4 filesystem.
    ///
    /// The filesystem walk starts at the root directory and
    /// descends the whole directory hierarchy, converting the
    /// discovered EXT4 objects into their filesystem-independent
    /// forensic representation.
    ///
    /// This compatibility API performs the investigation without
    /// reporting progress.
    pub fn investigate<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
    ) -> Result<Ext4Investigation> {
        investigate_filesystem(self, reader)
    }

    /// Investigates the EXT4 filesystem and reports progress.
    ///
    /// The reachable-directory walk is reported as an indeterminate
    /// inode counter. The inode table scan for deleted files reports
    /// a determinate percentage because the total inode count is known.
    pub fn investigate_with_progress<R: Readable>(
        &self,
        reader: &mut Ext4Reader<R>,
        reporter: &dyn crate::progress::ProgressReporter,
    ) -> Result<Ext4Investigation> {
        investigate_filesystem_with_progress(self, reader, reporter)
    }
}

use crate::error::ForensisError;
use crate::result::Result;

/// Represents the inode table of an EXT4 block group.
///
/// The inode table contains the actual inode structures.
/// Each inode occupies a fixed-size slot in the table.
///
/// The table itself does not interpret the inode contents.
/// It is responsible only for locating the raw bytes
/// belonging to each inode.
#[derive(Debug, Clone)]
pub struct Ext4InodeTable {
    data: Vec<u8>,
    inode_size: u16,
}

impl Ext4InodeTable {
    /// Creates an inode table from raw bytes.
    ///
    /// `inode_size` is the size of one inode as defined
    /// by the EXT4 superblock.
    pub fn parse(data: &[u8], inode_size: u16) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty EXT4 inode table".to_string(),
            ));
        }

        if inode_size == 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inode size".to_string(),
            ));
        }

        let inode_size_usize = inode_size as usize;

        if inode_size_usize > data.len() {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode size exceeds table size".to_string(),
            ));
        }

        if data.len() % inode_size_usize != 0 {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode table contains incomplete inode data".to_string(),
            ));
        }

        Ok(Self {
            data: data.to_vec(),
            inode_size,
        })
    }

    /// Returns the inode size in bytes.
    pub fn inode_size(&self) -> u16 {
        self.inode_size
    }

    /// Returns the total number of complete inodes
    /// represented by this table.
    pub fn inode_count(&self) -> u64 {
        (self.data.len() / self.inode_size as usize) as u64
    }

    /// Returns the raw bytes of an inode by zero-based index.
    ///
    /// The returned slice contains exactly one inode.
    pub fn inode(&self, index: u64) -> Result<&[u8]> {
        if index >= self.inode_count() {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode index out of bounds".to_string(),
            ));
        }

        let size = self.inode_size as usize;
        let start = index as usize * size;
        let end = start + size;

        Ok(&self.data[start..end])
    }

    /// Returns the byte offset of an inode inside the table.
    pub fn inode_offset(&self, index: u64) -> Result<u64> {
        if index >= self.inode_count() {
            return Err(ForensisError::InvalidFormat(
                "EXT4 inode index out of bounds".to_string(),
            ));
        }

        Ok(index * self.inode_size as u64)
    }

    /// Returns the raw inode table.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns the size of the entire inode table in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns true when the table contains the specified inode index.
    pub fn contains(&self, index: u64) -> bool {
        index < self.inode_count()
    }
}

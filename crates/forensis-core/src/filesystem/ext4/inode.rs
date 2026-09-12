use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 inode.
///
/// The inode stores metadata about a filesystem object.
/// The filename itself is stored in the directory entry,
/// not inside the inode.
///
/// The `i_block` field stores the block mapping information
/// used by the filesystem. For modern EXT4 filesystems this
/// normally contains an extent tree.
#[derive(Debug, Clone)]
pub struct Ext4Inode {
    mode: u16,
    uid: u16,
    size_lo: u32,
    atime: u32,
    ctime: u32,
    mtime: u32,
    dtime: u32,
    gid: u16,
    links_count: u16,
    blocks_lo: u32,
    flags: u32,
    size_high: u32,
    blocks_high: u16,
    i_block: [u8; 60],
}

impl Ext4Inode {
    /// Minimum size of the traditional EXT4 inode.
    pub const MIN_SIZE: usize = 128;

    /// Offset of the `i_block` field inside the inode.
    const I_BLOCK_OFFSET: usize = 0x28;

    /// Size of the `i_block` field.
    pub const I_BLOCK_SIZE: usize = 60;

    /// Parses an EXT4 inode from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 inode: insufficient data".to_string(),
            ));
        }

        let mode = u16::from_le_bytes([data[0x00], data[0x01]]);

        let uid = u16::from_le_bytes([data[0x02], data[0x03]]);

        let size_lo = u32::from_le_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]);

        let atime = u32::from_le_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]);

        let ctime = u32::from_le_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]);

        let mtime = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);

        let dtime = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);

        let gid = u16::from_le_bytes([data[0x18], data[0x19]]);

        let links_count = u16::from_le_bytes([data[0x1A], data[0x1B]]);

        let blocks_lo = u32::from_le_bytes([data[0x1C], data[0x1D], data[0x1E], data[0x1F]]);

        let flags = u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]);

        /*
         * The extension fields below belong to the base inode
         * area and are always present when the inode contains
         * its traditional 128 bytes.
         *
         * On filesystems created without the EXT4 64-bit feature
         * these fields are zero, so combining them with the low
         * halves remains correct.
         */
        let size_high = u32::from_le_bytes([data[0x6C], data[0x6D], data[0x6E], data[0x6F]]);

        let blocks_high = u16::from_le_bytes([data[0x74], data[0x75]]);

        let mut i_block = [0u8; Self::I_BLOCK_SIZE];

        i_block.copy_from_slice(
            &data[Self::I_BLOCK_OFFSET..Self::I_BLOCK_OFFSET + Self::I_BLOCK_SIZE],
        );

        Ok(Self {
            mode,
            uid,
            size_lo,
            atime,
            ctime,
            mtime,
            dtime,
            gid,
            links_count,
            blocks_lo,
            flags,
            size_high,
            blocks_high,
            i_block,
        })
    }

    /// Returns the inode mode and file type.
    pub fn mode(&self) -> u16 {
        self.mode
    }

    /// Returns the owner user ID.
    pub fn uid(&self) -> u16 {
        self.uid
    }

    /// Returns the low 32 bits of the file size.
    pub fn size_lo(&self) -> u32 {
        self.size_lo
    }

    /// Returns the high 32 bits of the file size.
    pub fn size_high(&self) -> u32 {
        self.size_high
    }

    /// Returns the full 64-bit file size.
    ///
    /// The high word is combined with the low word, allowing
    /// files larger than 4 GiB to be represented.
    pub fn size(&self) -> u64 {
        ((self.size_high as u64) << 32) | self.size_lo as u64
    }

    /// Returns the access timestamp.
    pub fn atime(&self) -> u32 {
        self.atime
    }

    /// Returns the creation/change timestamp.
    pub fn ctime(&self) -> u32 {
        self.ctime
    }

    /// Returns the modification timestamp.
    pub fn mtime(&self) -> u32 {
        self.mtime
    }

    /// Returns the deletion timestamp.
    pub fn dtime(&self) -> u32 {
        self.dtime
    }

    /// Returns the owner group ID.
    pub fn gid(&self) -> u16 {
        self.gid
    }

    /// Returns the number of hard links.
    pub fn links_count(&self) -> u16 {
        self.links_count
    }

    /// Returns the full number of filesystem blocks used.
    ///
    /// EXT4 counts allocation in 512-byte units, even when the
    /// filesystem block size is larger. The caller must multiply
    /// by 512 to obtain the allocated byte count.
    pub fn blocks(&self) -> u64 {
        ((self.blocks_high as u64) << 32) | self.blocks_lo as u64
    }

    /// Returns the high 16 bits of the block count.
    pub fn blocks_high(&self) -> u16 {
        self.blocks_high
    }

    /// Returns inode flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the raw `i_block` field.
    ///
    /// The returned bytes contain the block mapping information
    /// of the inode. Modern EXT4 filesystems normally use this
    /// area for the extent tree.
    pub fn i_block(&self) -> &[u8; Self::I_BLOCK_SIZE] {
        &self.i_block
    }

    /// Returns true when the inode represents a directory.
    pub fn is_directory(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }

    /// Returns true when the inode represents a regular file.
    pub fn is_regular_file(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }

    /// Returns true when the inode represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }

    /// Returns the target of a fast symbolic link.
    ///
    /// A fast symlink stores its target inside the `i_block`
    /// area instead of using data blocks. When the target
    /// length fits that area, it is returned inline.
    pub fn fast_symlink_target(&self) -> Option<Vec<u8>> {
        if !self.is_symlink() {
            return None;
        }

        let length = usize::try_from(self.size()).ok()?;

        if length > self.i_block.len() {
            return None;
        }

        Some(self.i_block[..length].to_vec())
    }
}

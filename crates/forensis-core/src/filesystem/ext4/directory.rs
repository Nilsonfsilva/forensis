use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 directory entry.
///
/// A directory entry maps a filename to an inode.
///
/// The inode contains the metadata of the object,
/// while the directory entry contains the name and
/// the relationship between the directory and the object.
///
/// EXT4 directory entries are variable-sized.
#[derive(Debug, Clone)]
pub struct Ext4DirectoryEntry {
    inode: u32,
    record_length: u16,
    name_length: u8,
    file_type: u8,
    name: String,
}

impl Ext4DirectoryEntry {
    /// Minimum size of the fixed directory entry header.
    pub const HEADER_SIZE: usize = 8;

    /// Parses one EXT4 directory entry from raw bytes.
    ///
    /// The caller is responsible for providing the bytes
    /// corresponding to one directory entry.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 directory entry: insufficient data".to_string(),
            ));
        }

        let inode = u32::from_le_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]);

        let record_length = u16::from_le_bytes([data[0x04], data[0x05]]);

        let name_length = data[0x06];
        let file_type = data[0x07];

        if record_length < Self::HEADER_SIZE as u16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 directory entry record length".to_string(),
            ));
        }

        let name_end = Self::HEADER_SIZE + name_length as usize;

        if name_end > record_length as usize {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 directory entry name length".to_string(),
            ));
        }

        if name_end > data.len() {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 directory entry: truncated name".to_string(),
            ));
        }

        let name_bytes = &data[Self::HEADER_SIZE..name_end];

        let name = String::from_utf8_lossy(name_bytes).to_string();

        Ok(Self {
            inode,
            record_length,
            name_length,
            file_type,
            name,
        })
    }

    /// Parses all directory entries contained in a block.
    ///
    /// EXT4 directory entries are stored consecutively.
    /// Each entry defines the size of the next entry through
    /// its `record_length` field.
    pub fn parse_block(data: &[u8]) -> Result<Vec<Self>> {
        let mut entries = Vec::new();
        let mut offset = 0usize;

        while offset < data.len() {
            let remaining = &data[offset..];

            if remaining.len() < Self::HEADER_SIZE {
                break;
            }

            let record_length = u16::from_le_bytes([remaining[0x04], remaining[0x05]]) as usize;

            if record_length == 0 {
                break;
            }

            if record_length < Self::HEADER_SIZE {
                return Err(ForensisError::InvalidFormat(
                    "Invalid EXT4 directory entry record length".to_string(),
                ));
            }

            if offset + record_length > data.len() {
                return Err(ForensisError::InvalidFormat(
                    "EXT4 directory entry exceeds block boundary".to_string(),
                ));
            }

            let entry_data = &data[offset..offset + record_length];

            let entry = Self::parse(entry_data)?;

            entries.push(entry);

            offset += record_length;
        }

        Ok(entries)
    }

    /// Returns the inode number referenced by this entry.
    pub fn inode(&self) -> u32 {
        self.inode
    }

    /// Returns the total size of this directory entry.
    pub fn record_length(&self) -> u16 {
        self.record_length
    }

    /// Returns the filename length.
    pub fn name_length(&self) -> u8 {
        self.name_length
    }

    /// Returns the EXT4 directory file type.
    pub fn file_type(&self) -> u8 {
        self.file_type
    }

    /// Returns the filename.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns true when this entry represents an unused
    /// directory record.
    ///
    /// In EXT4, an inode value of zero means that the
    /// directory entry is unused.
    pub fn is_unused(&self) -> bool {
        self.inode == 0
    }

    /// Returns true when this entry represents a regular file.
    pub fn is_regular_file(&self) -> bool {
        self.file_type == 1
    }

    /// Returns true when this entry represents a directory.
    pub fn is_directory(&self) -> bool {
        self.file_type == 2
    }

    /// Returns true when this entry represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type == 7
    }
}

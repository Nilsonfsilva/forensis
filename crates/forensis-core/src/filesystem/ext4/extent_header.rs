use crate::error::ForensisError;
use crate::result::Result;

/// EXT4 extent tree header.
///
/// The extent header is stored at the beginning of the
/// inode `i_block` field or at the beginning of an external
/// extent tree block.
#[derive(Debug, Clone)]
pub struct Ext4ExtentHeader {
    magic: u16,
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
}

impl Ext4ExtentHeader {
    /// Size of an EXT4 extent tree header.
    pub const SIZE: usize = 12;

    /// EXT4 extent tree magic value.
    pub const MAGIC: u16 = 0xF30A;

    /// Parses an EXT4 extent tree header.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 extent header: insufficient data".to_string(),
            ));
        }

        let magic = u16::from_le_bytes([data[0x00], data[0x01]]);

        if magic != Self::MAGIC {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 extent header magic".to_string(),
            ));
        }

        let entries = u16::from_le_bytes([data[0x02], data[0x03]]);

        let max = u16::from_le_bytes([data[0x04], data[0x05]]);

        let depth = u16::from_le_bytes([data[0x06], data[0x07]]);

        let generation = u32::from_le_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]);

        if entries > max {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 extent header: entries exceed maximum".to_string(),
            ));
        }

        Ok(Self {
            magic,
            entries,
            max,
            depth,
            generation,
        })
    }

    /// Returns the extent tree magic value.
    pub fn magic(&self) -> u16 {
        self.magic
    }

    /// Returns the number of valid entries.
    pub fn entries(&self) -> u16 {
        self.entries
    }

    /// Returns the maximum number of entries supported
    /// by this extent tree node.
    pub fn max(&self) -> u16 {
        self.max
    }

    /// Returns the depth of this extent tree node.
    ///
    /// A depth of zero means the node contains extents.
    /// A depth greater than zero means the node contains
    /// indexes to child nodes.
    pub fn depth(&self) -> u16 {
        self.depth
    }

    /// Returns the extent tree generation number.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Returns true when this node directly contains extents.
    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }

    /// Returns true when this node contains indexes to
    /// child extent tree nodes.
    pub fn is_index(&self) -> bool {
        self.depth > 0
    }
}

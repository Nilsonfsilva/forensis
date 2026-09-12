use crate::error::ForensisError;
use crate::result::Result;

use super::Ext4BlockGroupDescriptor;

/// Represents the EXT4 block group descriptor table.
#[derive(Debug, Clone)]
pub struct Ext4BlockGroupTable {
    descriptors: Vec<Ext4BlockGroupDescriptor>,
}

impl Ext4BlockGroupTable {
    /// Creates a block group descriptor table from raw data.
    ///
    /// EXT4 uses a 32-byte descriptor in the traditional
    /// descriptor format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty EXT4 block group descriptor table".to_string(),
            ));
        }

        if data.len() % Ext4BlockGroupDescriptor::SIZE != 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid EXT4 block group descriptor table size".to_string(),
            ));
        }

        let mut descriptors = Vec::new();

        for chunk in data.chunks(Ext4BlockGroupDescriptor::SIZE) {
            descriptors.push(Ext4BlockGroupDescriptor::parse(chunk)?);
        }

        Ok(Self { descriptors })
    }

    /// Returns the number of block groups.
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// Returns true if the table contains no descriptors.
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Returns a descriptor by block group number.
    pub fn get(&self, index: usize) -> Option<&Ext4BlockGroupDescriptor> {
        self.descriptors.get(index)
    }

    /// Returns all descriptors.
    pub fn descriptors(&self) -> &[Ext4BlockGroupDescriptor] {
        &self.descriptors
    }
}

use crate::error::ForensisError;
use crate::result::Result;

/// Basic representation of the EXT4 journal.
///
/// The journal is used by EXT4 to record filesystem
/// changes before they are committed to their final
/// locations.
#[derive(Debug, Clone)]
pub struct Ext4Journal {
    data: Vec<u8>,
}

impl Ext4Journal {
    /// Creates a journal from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty EXT4 journal".to_string(),
            ));
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns the raw journal data.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns the journal size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns true when the journal contains data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

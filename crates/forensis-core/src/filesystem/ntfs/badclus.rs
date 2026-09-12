use crate::error::ForensisError;
use crate::result::Result;

/// NTFS $BadClus attribute.
///
/// Stores clusters marked as unusable by NTFS.
#[derive(Debug, Clone)]
pub struct BadClusters {
    data: Vec<u8>,
}

impl BadClusters {
    /// Parses raw $BadClus data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty $BadClus data".to_string(),
            ));
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns raw bad cluster information.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns size of the structure.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

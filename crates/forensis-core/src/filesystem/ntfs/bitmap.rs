use crate::error::ForensisError;
use crate::result::Result;

/// Represents the NTFS $BITMAP attribute.
///
/// Each bit represents one cluster.
///
/// 1 = allocated
/// 0 = free
#[derive(Debug, Clone)]
pub struct Bitmap {
    data: Vec<u8>,
}

impl Bitmap {
    /// Creates a bitmap from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat("Empty bitmap".to_string()));
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns true if a cluster is allocated.
    pub fn is_allocated(&self, cluster: u64) -> bool {
        let byte = (cluster / 8) as usize;

        if byte >= self.data.len() {
            return false;
        }

        let bit = (cluster % 8) as u8;

        self.data[byte] & (1 << bit) != 0
    }

    /// Returns total clusters represented.
    pub fn cluster_count(&self) -> u64 {
        (self.data.len() * 8) as u64
    }

    /// Returns raw bitmap.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }
}

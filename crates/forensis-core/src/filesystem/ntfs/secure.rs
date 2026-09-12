use crate::error::ForensisError;
use crate::result::Result;

/// NTFS $Secure attribute.
///
/// Stores security descriptors used by NTFS
/// to manage file permissions.
#[derive(Debug, Clone)]
pub struct Secure {
    data: Vec<u8>,
}

impl Secure {
    /// Parses a raw $Secure stream.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat(
                "Empty $Secure data".to_string(),
            ));
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns the raw security data.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns size of the security descriptor stream.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

use crate::error::ForensisError;
use crate::result::Result;

/// NTFS $UpCase table.
///
/// The table contains Unicode uppercase mappings
/// used by NTFS for case-insensitive filename comparison.
#[derive(Debug, Clone)]
pub struct UpCase {
    table: Vec<u16>,
}

impl UpCase {
    /// Parses a raw $UpCase stream.
    ///
    /// Each entry is a UTF-16LE Unicode value.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat("Empty $UpCase".to_string()));
        }

        if data.len() % 2 != 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid $UpCase size".to_string(),
            ));
        }

        let mut table = Vec::new();

        for chunk in data.chunks_exact(2) {
            let value = u16::from_le_bytes([chunk[0], chunk[1]]);

            table.push(value);
        }

        Ok(Self { table })
    }

    /// Converts a UTF-16 character using
    /// the NTFS uppercase table.
    pub fn uppercase(&self, value: u16) -> u16 {
        let index = value as usize;

        if index < self.table.len() {
            return self.table[index];
        }

        value
    }

    /// Compares two UTF-16 strings using
    /// NTFS uppercase rules.
    pub fn equals_ignore_case(&self, a: &[u16], b: &[u16]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        for (x, y) in a.iter().zip(b.iter()) {
            if self.uppercase(*x) != self.uppercase(*y) {
                return false;
            }
        }

        true
    }

    /// Returns raw table entries.
    pub fn raw(&self) -> &[u16] {
        &self.table
    }
}

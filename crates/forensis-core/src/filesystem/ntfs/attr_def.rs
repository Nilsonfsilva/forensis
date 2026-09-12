use crate::error::ForensisError;
use crate::result::Result;

/// One entry from the NTFS $AttrDef file.
#[derive(Debug, Clone)]
pub struct AttributeDefinition {
    name: String,
    attribute_type: u32,
    flags: u32,
    minimum_size: u64,
    maximum_size: u64,
}

/// Represents the NTFS $AttrDef metadata file.
#[derive(Debug, Clone)]
pub struct AttrDef {
    entries: Vec<AttributeDefinition>,
}

impl AttrDef {
    /// Parses the raw contents of the NTFS $AttrDef file.
    ///
    /// Each entry occupies 160 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat("Empty $AttrDef".to_string()));
        }

        let mut entries = Vec::new();

        let mut offset = 0;

        while offset + 160 <= data.len() {
            let entry = &data[offset..offset + 160];

            // Empty name marks the end of the table.
            if entry[0] == 0 {
                break;
            }

            //
            // Attribute name (UTF-16LE)
            //
            let mut utf16 = Vec::new();

            for chunk in entry[..128].chunks_exact(2) {
                let value = u16::from_le_bytes([chunk[0], chunk[1]]);

                if value == 0 {
                    break;
                }

                utf16.push(value);
            }

            let name = String::from_utf16_lossy(&utf16);

            let attribute_type =
                u32::from_le_bytes([entry[128], entry[129], entry[130], entry[131]]);

            let flags = u32::from_le_bytes([entry[132], entry[133], entry[134], entry[135]]);

            let minimum_size = u64::from_le_bytes([
                entry[136], entry[137], entry[138], entry[139], entry[140], entry[141], entry[142],
                entry[143],
            ]);

            let maximum_size = u64::from_le_bytes([
                entry[144], entry[145], entry[146], entry[147], entry[148], entry[149], entry[150],
                entry[151],
            ]);

            entries.push(AttributeDefinition {
                name,
                attribute_type,
                flags,
                minimum_size,
                maximum_size,
            });

            offset += 160;
        }

        Ok(Self { entries })
    }

    /// Returns every parsed definition.
    pub fn entries(&self) -> &[AttributeDefinition] {
        &self.entries
    }
}

impl AttributeDefinition {
    /// Attribute name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// NTFS attribute type.
    pub fn attribute_type(&self) -> u32 {
        self.attribute_type
    }

    /// Attribute flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Minimum attribute size.
    pub fn minimum_size(&self) -> u64 {
        self.minimum_size
    }

    /// Maximum attribute size.
    pub fn maximum_size(&self) -> u64 {
        self.maximum_size
    }
}

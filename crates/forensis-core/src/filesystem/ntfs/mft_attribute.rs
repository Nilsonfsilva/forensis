use crate::error::ForensisError;
use crate::result::Result;

/// NTFS attribute types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    StandardInformation,
    AttributeList,
    FileName,
    ObjectId,
    SecurityDescriptor,
    VolumeName,
    VolumeInformation,
    Data,
    IndexRoot,
    IndexAllocation,
    Bitmap,
    ReparsePoint,
    ExtendedAttributeInformation,
    ExtendedAttribute,
    End,
    Unknown(u32),
}

impl AttributeType {
    pub fn from_raw(value: u32) -> Self {
        match value {
            0x10 => Self::StandardInformation,
            0x20 => Self::AttributeList,
            0x30 => Self::FileName,
            0x40 => Self::ObjectId,
            0x50 => Self::SecurityDescriptor,
            0x60 => Self::VolumeName,
            0x70 => Self::VolumeInformation,
            0x80 => Self::Data,
            0x90 => Self::IndexRoot,
            0xA0 => Self::IndexAllocation,
            0xB0 => Self::Bitmap,
            0xC0 => Self::ReparsePoint,
            0xD0 => Self::ExtendedAttributeInformation,
            0xE0 => Self::ExtendedAttribute,
            0xFFFFFFFF => Self::End,
            other => Self::Unknown(other),
        }
    }
}

/// Represents the common portion of an NTFS attribute.
#[derive(Debug, Clone)]
pub struct MftAttribute {
    pub attribute_type: AttributeType,
    pub length: u32,
    pub non_resident: bool,
    pub id: u16,
    pub data: Vec<u8>,
}

impl MftAttribute {
    /// Parses an NTFS attribute from the beginning of an attribute buffer.
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < 16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid MFT attribute header".to_string(),
            ));
        }

        let attribute_type_raw = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

        let attribute_type = AttributeType::from_raw(attribute_type_raw);

        if attribute_type == AttributeType::End {
            return Ok(Self {
                attribute_type,
                length: 0,
                non_resident: false,
                id: 0,
                data: Vec::new(),
            });
        }

        let length = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

        if length < 16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid MFT attribute length".to_string(),
            ));
        }

        if length as usize > buffer.len() {
            return Err(ForensisError::InvalidFormat(
                "MFT attribute exceeds record".to_string(),
            ));
        }

        let non_resident = buffer[8] != 0;

        let id = u16::from_le_bytes([buffer[14], buffer[15]]);

        /*
         * Unknown attributes are not interpreted by the
         * filesystem-specific parser.
         *
         * We still validate their common header and declared
         * length because those fields are necessary to advance
         * safely to the next attribute.
         */
        if matches!(attribute_type, AttributeType::Unknown(_)) {
            return Ok(Self {
                attribute_type,
                length,
                non_resident,
                id,
                data: Vec::new(),
            });
        }

        /*
         * Non-resident attributes do not contain their complete
         * value directly in the attribute.
         *
         * Their contents are interpreted later through the
         * attribute-specific structures and data runs.
         */
        let data = if non_resident {
            Vec::new()
        } else {
            /*
             * Resident attributes contain:
             *
             * Offset 16..20 = value length
             * Offset 20..22 = value offset
             */
            if (length as usize) < 22 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid resident attribute header".to_string(),
                ));
            }

            let value_length =
                u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]) as usize;

            let value_offset = u16::from_le_bytes([buffer[20], buffer[21]]) as usize;

            let value_end = value_offset.checked_add(value_length).ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid attribute value range".to_string())
            })?;

            if value_offset < 22 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid attribute value offset".to_string(),
                ));
            }

            if value_end > length as usize {
                return Err(ForensisError::InvalidFormat(
                    "Attribute value exceeds attribute length".to_string(),
                ));
            }

            buffer[value_offset..value_end].to_vec()
        };

        Ok(Self {
            attribute_type,
            length,
            non_resident,
            id,
            data,
        })
    }
}

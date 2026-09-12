use crate::error::ForensisError;
use crate::result::Result;

/// NTFS $FILE_NAME attribute type.
pub const FILE_NAME_ATTRIBUTE_TYPE: u32 = 0x30;

/// Mask for the 48-bit MFT record number.
///
/// An NTFS file reference is a 64-bit value:
///
/// - bits 0..47  -> MFT record number
/// - bits 48..63 -> sequence number
pub const MFT_REFERENCE_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Size of the fixed $FILE_NAME value.
///
/// The filename itself begins at offset 66.
const FILE_NAME_VALUE_FIXED_SIZE: usize = 66;

/// Represents the parsed content of an NTFS
/// $FILE_NAME attribute.
#[derive(Debug, Clone)]
pub struct FileNameAttribute {
    /// MFT record number of the parent directory.
    pub parent_record: u64,

    /// Sequence number stored in the parent file reference.
    ///
    /// This is preserved because it is useful for forensic
    /// validation of references.
    pub parent_sequence: u16,

    /// Namespace used by the filename.
    ///
    /// NTFS namespaces:
    ///
    /// 0 = POSIX
    /// 1 = Win32
    /// 2 = DOS
    /// 3 = Win32 + DOS
    pub namespace: u8,

    /// Filename.
    pub name: String,

    /// Allocated size of the file.
    pub allocated_size: u64,

    /// Real size of the file.
    pub real_size: u64,

    /// NTFS file attributes.
    pub file_attributes: u32,
}

impl FileNameAttribute {
    /// Parses a complete NTFS $FILE_NAME attribute.
    ///
    /// The input buffer begins at the NTFS attribute header.
    ///
    /// This method is used when the $FILE_NAME attribute
    /// comes directly from an MFT record.
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        /*
         * ---------------------------------------------------------
         * COMMON ATTRIBUTE HEADER
         * ---------------------------------------------------------
         *
         * 0x00 -> Attribute type
         * 0x04 -> Attribute length
         * 0x08 -> Non-resident flag
         */

        if buffer.len() < 16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid FILE_NAME attribute".to_string(),
            ));
        }

        let attribute_type = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

        if attribute_type != FILE_NAME_ATTRIBUTE_TYPE {
            return Err(ForensisError::InvalidFormat(
                "Not a FILE_NAME attribute".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * ATTRIBUTE LENGTH
         * ---------------------------------------------------------
         */

        let attribute_length =
            u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;

        if attribute_length < 24 || attribute_length > buffer.len() {
            return Err(ForensisError::InvalidFormat(
                "Invalid FILE_NAME attribute length".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * FILE_NAME MUST BE RESIDENT
         * ---------------------------------------------------------
         */

        if buffer[8] != 0 {
            return Err(ForensisError::InvalidFormat(
                "FILE_NAME attribute must be resident".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * RESIDENT ATTRIBUTE HEADER
         * ---------------------------------------------------------
         *
         * 0x10 -> value length
         * 0x14 -> value offset
         */

        if buffer.len() < 24 {
            return Err(ForensisError::InvalidFormat(
                "Truncated FILE_NAME attribute header".to_string(),
            ));
        }

        let value_length =
            u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]) as usize;

        let value_offset = u16::from_le_bytes([buffer[20], buffer[21]]) as usize;

        if value_offset < 24 {
            return Err(ForensisError::InvalidFormat(
                "Invalid FILE_NAME value offset".to_string(),
            ));
        }

        let value_end = value_offset.checked_add(value_length).ok_or_else(|| {
            ForensisError::InvalidFormat("Invalid FILE_NAME value range".to_string())
        })?;

        if value_end > attribute_length || value_end > buffer.len() {
            return Err(ForensisError::InvalidFormat(
                "FILE_NAME value exceeds attribute".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * PARSE THE FILE_NAME VALUE
         * ---------------------------------------------------------
         */

        Self::parse_value(&buffer[value_offset..value_end])
    }

    /// Parses the FILE_NAME value itself.
    ///
    /// This is used by both:
    ///
    /// 1. a complete $FILE_NAME attribute from an MFT record;
    /// 2. an INDEX_ENTRY key.
    ///
    /// An INDEX_ENTRY key does NOT contain the NTFS attribute
    /// header. It begins directly with the FILE_NAME value.
    pub fn parse_value(value: &[u8]) -> Result<Self> {
        /*
         * ---------------------------------------------------------
         * FIXED FILE_NAME VALUE
         * ---------------------------------------------------------
         *
         * The fixed portion occupies 66 bytes:
         *
         * 0x00 -> Parent file reference
         * 0x08 -> Creation time
         * 0x10 -> Modification time
         * 0x18 -> MFT modification time
         * 0x20 -> Access time
         * 0x28 -> Allocated size
         * 0x30 -> Real size
         * 0x38 -> File attributes
         * 0x3C -> Extended attributes / reparse
         * 0x40 -> Filename length
         * 0x41 -> Namespace
         * 0x42 -> Filename
         */

        if value.len() < FILE_NAME_VALUE_FIXED_SIZE {
            return Err(ForensisError::InvalidFormat(
                "Truncated FILE_NAME value".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * PARENT FILE REFERENCE
         * ---------------------------------------------------------
         */

        let parent_reference = u64::from_le_bytes([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]);

        let parent_record = parent_reference & MFT_REFERENCE_MASK;

        let parent_sequence = (parent_reference >> 48) as u16;

        /*
         * ---------------------------------------------------------
         * FILE SIZE
         * ---------------------------------------------------------
         */

        let allocated_size = u64::from_le_bytes([
            value[40], value[41], value[42], value[43], value[44], value[45], value[46], value[47],
        ]);

        let real_size = u64::from_le_bytes([
            value[48], value[49], value[50], value[51], value[52], value[53], value[54], value[55],
        ]);

        /*
         * ---------------------------------------------------------
         * FILE ATTRIBUTES
         * ---------------------------------------------------------
         */

        let file_attributes = u32::from_le_bytes([value[56], value[57], value[58], value[59]]);

        /*
         * ---------------------------------------------------------
         * FILENAME METADATA
         * ---------------------------------------------------------
         */

        let name_length = value[64] as usize;

        let namespace = value[65];

        /*
         * Each filename character occupies
         * two bytes in UTF-16LE.
         */

        let name_size = name_length
            .checked_mul(2)
            .ok_or_else(|| ForensisError::InvalidFormat("Invalid FILE_NAME length".to_string()))?;

        let name_end = FILE_NAME_VALUE_FIXED_SIZE
            .checked_add(name_size)
            .ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid FILE_NAME name range".to_string())
            })?;

        if name_end > value.len() {
            return Err(ForensisError::InvalidFormat(
                "FILE_NAME name exceeds value".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * DECODE UTF-16LE FILENAME
         * ---------------------------------------------------------
         */

        let name_bytes = &value[FILE_NAME_VALUE_FIXED_SIZE..name_end];

        let mut utf16 = Vec::with_capacity(name_length);

        for chunk in name_bytes.chunks_exact(2) {
            utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }

        let name = String::from_utf16(&utf16)
            .map_err(|_| ForensisError::InvalidFormat("Invalid UTF-16 FILE_NAME".to_string()))?;

        Ok(Self {
            parent_record,
            parent_sequence,
            namespace,
            name,
            allocated_size,
            real_size,
            file_attributes,
        })
    }

    /// Returns true if the FILE_NAME represents
    /// a directory.
    ///
    /// NTFS FILE_ATTRIBUTE_DIRECTORY:
    ///
    /// 0x10000000
    pub fn is_directory(&self) -> bool {
        self.file_attributes & 0x10000000 != 0
    }

    /// Returns true if the FILE_NAME represents
    /// a regular file.
    pub fn is_file(&self) -> bool {
        !self.is_directory()
    }
}

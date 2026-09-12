use crate::error::ForensisError;
use crate::result::Result;

use super::file_name::FileNameAttribute;

/// Represents one entry inside an NTFS directory index.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Raw NTFS file reference.
    ///
    /// The NTFS file reference is composed of:
    ///
    /// - lower 48 bits: MFT record number
    /// - upper 16 bits: sequence number
    pub file_reference: u64,

    /// Total size of the index entry.
    pub entry_length: u16,

    /// Size of the key data.
    pub key_length: u16,

    /// Entry flags.
    pub flags: u16,

    /// Raw key data.
    pub key: Vec<u8>,
}

impl IndexEntry {
    /// Parses an INDEX_ENTRY.
    ///
    /// This method is responsible only for parsing the
    /// structural INDEX_ENTRY header and its raw key.
    ///
    /// It intentionally allows key_length == 0.
    /// Interpretation of the key as FILE_NAME belongs to
    /// `file_name()`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        /*
         * ---------------------------------------------------------
         * INDEX_ENTRY HEADER
         * ---------------------------------------------------------
         *
         * Offset 00: File reference
         * Offset 08: Entry length
         * Offset 10: Key length
         * Offset 12: Flags
         * Offset 14: Reserved
         *
         * The fixed structure is 16 bytes.
         */

        if data.len() < 16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ENTRY".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * MFT FILE REFERENCE
         * ---------------------------------------------------------
         *
         * NTFS stores the file reference as a 64-bit value:
         *
         *   bits  0..47 = MFT record number
         *   bits 48..63 = sequence number
         *
         * We preserve the complete raw value here.
         * The individual components are exposed through:
         *
         *   mft_record()
         *   sequence_number()
         */

        let file_reference = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        /*
         * ---------------------------------------------------------
         * ENTRY LENGTH
         * ---------------------------------------------------------
         */

        let entry_length = u16::from_le_bytes([data[8], data[9]]);

        /*
         * ---------------------------------------------------------
         * KEY LENGTH
         * ---------------------------------------------------------
         */

        let key_length = u16::from_le_bytes([data[10], data[11]]);

        /*
         * ---------------------------------------------------------
         * FLAGS
         * ---------------------------------------------------------
         */

        let flags = u16::from_le_bytes([data[12], data[13]]);

        /*
         * ---------------------------------------------------------
         * VALIDATE ENTRY LENGTH
         * ---------------------------------------------------------
         *
         * Every INDEX_ENTRY must contain at least its
         * fixed 16-byte header.
         */

        if entry_length < 16 {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ENTRY length".to_string(),
            ));
        }

        /*
         * The complete INDEX_ENTRY must be available
         * in the supplied buffer.
         */

        let entry_end = entry_length as usize;

        if entry_end > data.len() {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ENTRY exceeds buffer".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * KEY
         * ---------------------------------------------------------
         *
         * The key starts immediately after the fixed
         * 16-byte INDEX_ENTRY header.
         */

        let key_offset = 16usize;

        let key_end = key_offset.checked_add(key_length as usize).ok_or_else(|| {
            ForensisError::InvalidFormat("Invalid INDEX_ENTRY key range".to_string())
        })?;

        /*
         * The key must remain inside the INDEX_ENTRY.
         *
         * key_length == 0 is allowed.
         *
         * This is important because the terminating
         * INDEX_ENTRY and structural test records may
         * contain no key.
         */

        if key_end > entry_end {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ENTRY key exceeds entry".to_string(),
            ));
        }

        /*
         * Preserve the raw key.
         */

        let key = data[key_offset..key_end].to_vec();

        Ok(Self {
            file_reference,
            entry_length,
            key_length,
            flags,
            key,
        })
    }

    /// Returns the MFT record number referenced by this entry.
    ///
    /// NTFS uses only the lower 48 bits of the file reference
    /// for the MFT record number.
    pub fn mft_record(&self) -> u64 {
        self.file_reference & 0x0000_FFFF_FFFF_FFFF
    }

    /// Returns the NTFS sequence number of this reference.
    ///
    /// The sequence number occupies the upper 16 bits
    /// of the 64-bit NTFS file reference.
    pub fn sequence_number(&self) -> u16 {
        (self.file_reference >> 48) as u16
    }

    /// Returns the raw NTFS file reference.
    ///
    /// This preserves both the MFT record number and
    /// sequence number exactly as stored on disk.
    pub fn raw_file_reference(&self) -> u64 {
        self.file_reference
    }

    /// Returns the raw key bytes.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Parses the key as an NTFS FILE_NAME attribute.
    ///
    /// This is deliberately separate from `parse()`.
    ///
    /// An INDEX_ENTRY may be structurally valid even when
    /// it has no key, while a FILE_NAME interpretation
    /// requires at least the fixed FILE_NAME structure.
    pub fn file_name(&self) -> Result<FileNameAttribute> {
        /*
         * A FILE_NAME attribute has a fixed portion
         * of 66 bytes before the variable-length name.
         */

        if self.key.len() < 66 {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ENTRY key is too small for FILE_NAME".to_string(),
            ));
        }
        FileNameAttribute::parse_value(&self.key)
    }

    /// Returns true if this entry is the final
    /// INDEX_ENTRY in the index.
    pub fn is_last(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Returns true if this entry has a child node.
    ///
    /// NTFS uses bit 0x0001 to indicate that the
    /// INDEX_ENTRY contains a sub-node pointer.
    pub fn has_sub_node(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Returns the raw bytes of the entry.
    pub fn raw(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.entry_length as usize);

        /*
         * File reference.
         */

        data.extend_from_slice(&self.file_reference.to_le_bytes());

        /*
         * Entry length.
         */

        data.extend_from_slice(&self.entry_length.to_le_bytes());

        /*
         * Key length.
         */

        data.extend_from_slice(&self.key_length.to_le_bytes());

        /*
         * Flags.
         */

        data.extend_from_slice(&self.flags.to_le_bytes());

        /*
         * Reserved field.
         *
         * The original raw value is not currently stored
         * in the structure, so it is reconstructed as zero.
         */

        data.extend_from_slice(&0u16.to_le_bytes());

        /*
         * Raw key.
         */

        data.extend_from_slice(&self.key);

        data
    }
}

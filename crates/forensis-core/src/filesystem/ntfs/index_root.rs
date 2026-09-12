use crate::error::ForensisError;
use crate::result::Result;

use super::index_entry::IndexEntry;

/// Size of the fixed part of the NTFS INDEX_ROOT header.
const INDEX_ROOT_HEADER_SIZE: usize = 16;

/// Size of the NTFS INDEX_HEADER.
const INDEX_HEADER_SIZE: usize = 16;

/// Represents an NTFS INDEX_ROOT attribute.
#[derive(Debug, Clone)]
pub struct IndexRoot {
    /// Attribute type being indexed.
    pub indexed_attribute_type: u32,

    /// Collation rule used by the index.
    pub collation_rule: u32,

    /// Size of each index allocation block.
    pub index_block_size: u32,

    /// Index entries contained in this root.
    pub entries: Vec<IndexEntry>,
}

impl IndexRoot {
    /// Parses an INDEX_ROOT attribute value.
    pub fn parse(data: &[u8]) -> Result<Self> {
        /*
         * ---------------------------------------------------------
         * INDEX_ROOT HEADER
         * ---------------------------------------------------------
         *
         * Offset 00: Attribute type being indexed
         * Offset 04: Collation rule
         * Offset 08: Index block size
         * Offset 12: Clusters per index block
         */

        if data.len() < INDEX_ROOT_HEADER_SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ROOT size".to_string(),
            ));
        }

        let indexed_attribute_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let collation_rule = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let index_block_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        /*
         * ---------------------------------------------------------
         * INDEX_HEADER
         * ---------------------------------------------------------
         *
         * The INDEX_HEADER starts immediately after the
         * 16-byte INDEX_ROOT header.
         *
         * Offset 00: Offset to first INDEX_ENTRY
         * Offset 04: Total size of INDEX_HEADER + entries
         * Offset 08: Allocated size
         * Offset 12: Flags
         */

        if data.len() < INDEX_ROOT_HEADER_SIZE + INDEX_HEADER_SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ROOT header".to_string(),
            ));
        }

        let index_header_offset = INDEX_ROOT_HEADER_SIZE;

        let entries_offset_relative = u32::from_le_bytes([
            data[index_header_offset],
            data[index_header_offset + 1],
            data[index_header_offset + 2],
            data[index_header_offset + 3],
        ]) as usize;

        let entries_size = u32::from_le_bytes([
            data[index_header_offset + 4],
            data[index_header_offset + 5],
            data[index_header_offset + 6],
            data[index_header_offset + 7],
        ]) as usize;

        /*
         * The offset to the first INDEX_ENTRY is relative
         * to the beginning of INDEX_HEADER.
         */

        let entries_offset = index_header_offset
            .checked_add(entries_offset_relative)
            .ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid INDEX_ROOT entry offset".to_string())
            })?;

        /*
         * The total size field includes the INDEX_HEADER
         * itself and all INDEX_ENTRY structures.
         */

        if entries_size < INDEX_HEADER_SIZE {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ROOT entries size".to_string(),
            ));
        }

        let entries_end = index_header_offset
            .checked_add(entries_size)
            .ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid INDEX_ROOT entries range".to_string())
            })?;

        /*
         * The entries must remain inside both the
         * INDEX_ROOT value and the INDEX_HEADER's
         * declared range.
         */

        if entries_end > data.len() {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ROOT entries exceed attribute value".to_string(),
            ));
        }

        if entries_offset >= entries_end {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ROOT entry offset".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * Parse INDEX_ENTRY structures
         * ---------------------------------------------------------
         */

        let mut entries = Vec::new();

        let mut offset = entries_offset;

        while offset + 16 <= entries_end {
            /*
             * INDEX_ENTRY:
             *
             * Offset 00: File reference
             * Offset 08: Entry length
             * Offset 10: Key length
             * Offset 12: Flags
             * Offset 14: Reserved
             */

            let entry_length = u16::from_le_bytes([data[offset + 8], data[offset + 9]]) as usize;

            let flags = u16::from_le_bytes([data[offset + 12], data[offset + 13]]);

            /*
             * Every INDEX_ENTRY must contain at least
             * its fixed 16-byte header.
             */

            if entry_length < 16 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid INDEX_ENTRY length".to_string(),
                ));
            }

            let entry_end = offset.checked_add(entry_length).ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid INDEX_ENTRY range".to_string())
            })?;

            if entry_end > entries_end {
                return Err(ForensisError::InvalidFormat(
                    "INDEX_ENTRY exceeds INDEX_ROOT entries".to_string(),
                ));
            }

            /*
             * The LAST_ENTRY flag identifies the terminator.
             *
             * The terminator is not a real directory entry.
             */

            if flags & 0x0002 != 0 {
                break;
            }

            /*
             * Do not validate key_length here.
             *
             * IndexRoot is responsible for parsing the
             * structural INDEX_ENTRY.
             *
             * Interpretation of the key as FILE_NAME is
             * performed later by IndexEntry::file_name().
             *
             * This separation is important because a
             * structurally valid INDEX_ENTRY may have no
             * key, as demonstrated by structural tests.
             */

            /*
             * Parse the complete INDEX_ENTRY.
             */

            let entry = IndexEntry::parse(&data[offset..entry_end])?;

            entries.push(entry);

            offset = entry_end;
        }

        Ok(Self {
            indexed_attribute_type,
            collation_rule,
            index_block_size,
            entries,
        })
    }
}

use crate::error::ForensisError;
use crate::result::Result;

use super::index_entry::IndexEntry;

/// NTFS INDEX_ALLOCATION block signature: "INDX".
const INDX_SIGNATURE: &[u8; 4] = b"INDX";

/// Minimum size required to read an INDX block header.
const INDX_HEADER_SIZE: usize = 40;

/// Represents one NTFS INDEX_ALLOCATION block.
#[derive(Debug, Clone)]
pub struct IndexAllocation {
    data: Vec<u8>,
    entries: Vec<IndexEntry>,
}

impl IndexAllocation {
    /// Parses an INDEX_ALLOCATION block.
    ///
    /// The parser validates the INDX structure, applies the
    /// Update Sequence Array fixup and then parses the
    /// INDEX_ENTRY structures.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < INDX_HEADER_SIZE {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ALLOCATION block is too small".to_string(),
            ));
        }

        if &data[0..4] != INDX_SIGNATURE {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ALLOCATION signature".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * UPDATE SEQUENCE ARRAY
         * ---------------------------------------------------------
         *
         * INDX layout:
         *
         *   00  signature
         *   04  fixup offset
         *   06  fixup count
         *
         * The USA contains:
         *
         *   first value = Update Sequence Number
         *   following values = replacement bytes for each sector
         */

        let usa_offset = u16::from_le_bytes([data[4], data[5]]) as usize;

        let usa_count = u16::from_le_bytes([data[6], data[7]]) as usize;

        if usa_count < 2 {
            return Err(ForensisError::InvalidFormat(
                "Invalid INDEX_ALLOCATION USA count".to_string(),
            ));
        }

        let usa_end = usa_offset
            .checked_add(usa_count.checked_mul(2).ok_or_else(|| {
                ForensisError::InvalidFormat("INDEX_ALLOCATION USA size overflow".to_string())
            })?)
            .ok_or_else(|| {
                ForensisError::InvalidFormat("INDEX_ALLOCATION USA range overflow".to_string())
            })?;

        if usa_offset < 8 || usa_end > data.len() {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ALLOCATION USA exceeds block".to_string(),
            ));
        }

        let update_sequence = u16::from_le_bytes([data[usa_offset], data[usa_offset + 1]]);

        /*
         * Work on a private copy because the fixup modifies
         * the sector trailer bytes.
         */

        let mut fixed_data = data.to_vec();

        /*
         * The first USA entry is the sequence number.
         * Every following entry replaces the final two
         * bytes of one sector.
         *
         * The number of replacement values must match
         * the number of sectors represented by the block.
         *
         * INDEX_ALLOCATION records are normally sector aligned.
         * We derive the sector count from the USA count.
         */

        let replacement_count = usa_count - 1;

        if replacement_count == 0 {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ALLOCATION contains no fixup values".to_string(),
            ));
        }

        /*
         * NTFS INDX records are normally 512-byte-sector based.
         *
         * Forensic parsing should not blindly assume the input
         * buffer contains fewer sectors than described by the USA.
         */

        let sector_size = 512usize;

        for sector_index in 0..replacement_count {
            let sector_end = (sector_index + 1).checked_mul(sector_size).ok_or_else(|| {
                ForensisError::InvalidFormat("INDEX_ALLOCATION sector offset overflow".to_string())
            })?;

            if sector_end > fixed_data.len() {
                return Err(ForensisError::InvalidFormat(
                    "INDEX_ALLOCATION fixup exceeds block".to_string(),
                ));
            }

            let fixup_offset = usa_offset + 2 + sector_index * 2;

            let replacement =
                u16::from_le_bytes([fixed_data[fixup_offset], fixed_data[fixup_offset + 1]]);

            let trailer_offset = sector_end - 2;

            /*
             * The two bytes at the end of each sector must
             * contain the Update Sequence Number.
             */
            let trailer =
                u16::from_le_bytes([fixed_data[trailer_offset], fixed_data[trailer_offset + 1]]);

            if trailer != update_sequence {
                return Err(ForensisError::InvalidFormat(
                    "INDEX_ALLOCATION fixup sequence mismatch".to_string(),
                ));
            }

            fixed_data[trailer_offset..trailer_offset + 2]
                .copy_from_slice(&replacement.to_le_bytes());
        }

        /*
         * ---------------------------------------------------------
         * INDEX_HEADER
         * ---------------------------------------------------------
         *
         * The INDEX_HEADER begins at offset 24.
         */

        let index_header_offset = 24usize;

        let entries_offset_relative = u32::from_le_bytes([
            fixed_data[index_header_offset],
            fixed_data[index_header_offset + 1],
            fixed_data[index_header_offset + 2],
            fixed_data[index_header_offset + 3],
        ]) as usize;

        let entries_size = u32::from_le_bytes([
            fixed_data[index_header_offset + 4],
            fixed_data[index_header_offset + 5],
            fixed_data[index_header_offset + 6],
            fixed_data[index_header_offset + 7],
        ]) as usize;

        /*
         * The entry offset is relative to the beginning
         * of the INDEX_HEADER.
         */

        let entries_offset = index_header_offset
            .checked_add(entries_offset_relative)
            .ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid INDEX_ALLOCATION entry offset".to_string())
            })?;

        let entries_end = entries_offset.checked_add(entries_size).ok_or_else(|| {
            ForensisError::InvalidFormat("Invalid INDEX_ALLOCATION entry range".to_string())
        })?;

        if entries_offset > fixed_data.len() || entries_end > fixed_data.len() {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ALLOCATION entries exceed block".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * INDEX_ENTRY
         * ---------------------------------------------------------
         */

        let mut entries = Vec::new();

        let mut offset = entries_offset;

        while offset + 16 <= entries_end {
            let entry_length =
                u16::from_le_bytes([fixed_data[offset + 8], fixed_data[offset + 9]]) as usize;

            let flags = u16::from_le_bytes([fixed_data[offset + 12], fixed_data[offset + 13]]);

            /*
             * The final entry is a terminator and does not
             * contain a normal FILE_NAME key.
             */

            if flags & 0x0002 != 0 {
                break;
            }

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
                    "INDEX_ENTRY exceeds INDEX_ALLOCATION".to_string(),
                ));
            }

            let entry = IndexEntry::parse(&fixed_data[offset..entry_end])?;

            entries.push(entry);

            offset = entry_end;
        }

        Ok(Self {
            data: fixed_data,
            entries,
        })
    }

    /// Returns the raw INDEX_ALLOCATION block
    /// after USA fixup has been applied.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns the parsed INDEX_ENTRY records.
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// Returns the attribute size.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

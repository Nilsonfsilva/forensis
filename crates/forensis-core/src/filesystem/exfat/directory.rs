//! exFAT directory entry parsing.
//!
//! exFAT directories are plain sequences of 32-byte slots. A file is a
//! *record*: one file entry (`0x85`) followed by a stream extension
//! (`0xC0`) and one or more file name entries (`0xC1`, native UTF-16).
//!
//! Deleting a file only clears the in-use bit of every entry of the
//! record, which keeps the name units and the stream information
//! (start cluster and data length) recoverable until overwritten.

use chrono::{DateTime, TimeZone, Utc};

/// Directory attribute bit (shared with the FAT attribute set).
const ATTR_DIRECTORY: u8 = 0x10;

/// In-use bit: an entry whose type byte has this bit clear is deleted
/// or unused.
const IN_USE_BIT: u8 = 0x80;

/// File entry (live).
const ENTRY_FILE: u8 = 0x85;

/// Stream extension (live secondary entry).
const ENTRY_STREAM: u8 = 0xC0;

/// File name secondary entry (live).
const ENTRY_FILE_NAME: u8 = 0xC1;

/// Allocation bitmap entry.
const ENTRY_ALLOCATION_BITMAP: u8 = 0x81;

/// Up-case table entry.
const ENTRY_UP_CASE_TABLE: u8 = 0x82;

/// Volume label entry.
const ENTRY_VOLUME_LABEL: u8 = 0x83;

/// End-of-directory marker.
const END_MARK: u8 = 0xFF;

/// Number of UTF-16 units stored in one file name entry.
const NAME_UNITS_PER_ENTRY: usize = 15;

/// Kind of an exFAT directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExFatEntryKind {
    File,
    Directory,
    VolumeLabel,
    AllocationBitmap,
    UpCaseTable,
    Other,
}

/// One fully resolved exFAT directory record.
#[derive(Debug, Clone)]
pub struct ExFatDirectoryEntry {
    name: String,
    attributes: u8,
    cluster: u32,
    size: u64,
    deleted: bool,
    kind: ExFatEntryKind,

    /// Bytes in the file entry describing the record extent.
    secondary_count: u8,

    created_at: Option<DateTime<Utc>>,
    modified_at: Option<DateTime<Utc>>,
    accessed_at: Option<DateTime<Utc>>,
}

impl ExFatDirectoryEntry {
    /// Creates a directory entry.
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: String,
        attributes: u8,
        cluster: u32,
        size: u64,
        deleted: bool,
        kind: ExFatEntryKind,
        secondary_count: u8,
        created_at: Option<DateTime<Utc>>,
        modified_at: Option<DateTime<Utc>>,
        accessed_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            name,
            attributes,
            cluster,
            size,
            deleted,
            kind,
            secondary_count,
            created_at,
            modified_at,
            accessed_at,
        }
    }

    /// Returns the displayed (reconstructed) name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the raw attribute byte.
    pub fn attributes(&self) -> u8 {
        self.attributes
    }

    /// Returns the starting cluster from the stream extension.
    pub fn cluster(&self) -> u32 {
        self.cluster
    }

    /// Returns the file size in bytes (zero for directories).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns true when the record has been deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Returns the record kind.
    pub fn kind(&self) -> ExFatEntryKind {
        self.kind
    }

    /// Returns true when the record is a directory.
    pub fn is_directory(&self) -> bool {
        self.kind == ExFatEntryKind::Directory
    }

    /// Returns true when the record is the volume label.
    pub fn is_volume_label(&self) -> bool {
        self.kind == ExFatEntryKind::VolumeLabel
    }

    /// Returns true when the record is a filesystem system entry.
    pub fn is_system(&self) -> bool {
        matches!(
            self.kind,
            ExFatEntryKind::AllocationBitmap | ExFatEntryKind::UpCaseTable
        )
    }

    /// Returns the count of secondary entries following the file entry.
    pub fn secondary_count(&self) -> u8 {
        self.secondary_count
    }

    /// Returns the creation timestamp.
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        self.created_at
    }

    /// Returns the last modification timestamp.
    pub fn modified_at(&self) -> Option<DateTime<Utc>> {
        self.modified_at
    }

    /// Returns the last access timestamp.
    pub fn accessed_at(&self) -> Option<DateTime<Utc>> {
        self.accessed_at
    }
}

/// Decodes the timestamp stored in one 32-bit exFAT timestamp field.
///
/// The lower 16 bits encode the time (`2`-second granularity) and the
/// upper 16 bits the date. Timestamps with invalid or zero fields are
/// rejected. The value is interpreted as a local wall-clock time and
/// stored as UTC without an offset conversion.
fn decode_timestamp(raw: u32) -> Option<DateTime<Utc>> {
    if raw == 0 {
        return None;
    }

    let time = raw & 0xFFFF;
    let date = raw >> 16;

    let hour = (time >> 11) & 0x1F;
    let minute = (time >> 5) & 0x3F;
    let half_seconds = time & 0x1F;

    let day = date & 0x1F;
    let month = (date >> 5) & 0x0F;
    let year = 1980 + ((date >> 9) & 0x7F) as i32;

    if !(1..=12).contains(&month) {
        return None;
    }

    let lenient_days = if day < 1 { 1 } else { day.min(31) };

    let naive = chrono::NaiveDate::from_ymd_opt(year, month, lenient_days)?.and_hms_opt(
        hour,
        minute,
        half_seconds * 2,
    )?;

    Some(Utc.from_utc_datetime(&naive))
}

/// Parses all directory slots contained in `buffer`.
///
/// The function skips unused slots, stops at the end-of-directory
/// marker and reassembles one entry per file record found. Deleted
/// entries are returned together with their best-effort name when the
/// residual name entries are still present.
pub fn parse_directory_entries(buffer: &[u8]) -> Vec<ExFatDirectoryEntry> {
    let mut entries = Vec::new();

    let mut offset = 0usize;

    while offset + 32 <= buffer.len() {
        let slot = &buffer[offset..offset + 32];

        let type_byte = slot[0];

        if type_byte == END_MARK {
            break;
        }

        /*
         * Entries whose in-use bit is clear are free (zeroed) or
         * deleted (residual record with cleared type flags). A fully
         * zeroed slot marks unused space; a deleted record keeps the
         * low bits of its type so it can still be recognized.
         */
        if type_byte & IN_USE_BIT == 0 {
            if type_byte == 0x00 || type_byte == 0x03 {
                offset += 32;
                continue;
            }

            if let Some(entry) = parse_deleted_record(&buffer[offset..]) {
                entries.push(entry);
            }

            offset += 32;
            continue;
        }

        match type_byte {
            ENTRY_FILE => {
                if let Some(entry) = parse_file_record(&buffer[offset..]) {
                    entries.push(entry);
                }
            }

            ENTRY_VOLUME_LABEL => {
                if let Some(entry) = parse_volume_label(slot) {
                    entries.push(entry);
                }
            }

            ENTRY_ALLOCATION_BITMAP | ENTRY_UP_CASE_TABLE => {
                entries.push(ExFatDirectoryEntry::new(
                    system_entry_name(type_byte).to_string(),
                    0,
                    read_u32(slot, 4),
                    0,
                    false,
                    if type_byte == ENTRY_ALLOCATION_BITMAP {
                        ExFatEntryKind::AllocationBitmap
                    } else {
                        ExFatEntryKind::UpCaseTable
                    },
                    0,
                    None,
                    None,
                    None,
                ));
            }

            /*
             * Secondary entries (stream/name) are consumed as part of
             * the preceding file record. An orphan stream/name without
             * a file entry is skipped.
             */
            _ => {}
        }

        offset += 32;
    }

    entries
}

/// Builds the display name of a filesystem system entry.
fn system_entry_name(type_byte: u8) -> &'static str {
    match type_byte {
        ENTRY_ALLOCATION_BITMAP => "Allocation Bitmap",
        ENTRY_UP_CASE_TABLE => "Up-Case Table",
        _ => "System",
    }
}

/// Parses a live file record starting at `slot` (its file entry).
fn parse_file_record(buffer: &[u8]) -> Option<ExFatDirectoryEntry> {
    parse_record(buffer, false)
}

/// Parses a deleted file record starting at `slot`.
fn parse_deleted_record(buffer: &[u8]) -> Option<ExFatDirectoryEntry> {
    let type_byte = buffer[0];

    if type_byte != ENTRY_FILE & !IN_USE_BIT {
        return None;
    }

    parse_record(buffer, true)
}

/// Parses a file record (live or deleted) from its file entry slot.
///
/// `deleted` only influences the reported state; the same fields are
/// read because the deletion artifact keeps them intact.
fn parse_record(buffer: &[u8], deleted: bool) -> Option<ExFatDirectoryEntry> {
    let secondary_count = buffer[1];

    let attributes = u16::from_le_bytes([buffer[4], buffer[5]]) as u8;

    let name_length = u16::from_le_bytes([buffer[28], buffer[29]]);

    /*
     * The record covers the file entry plus secondary_count entries.
     * Only the stream (one) and the name entries (the rest) are
     * consumed; anything else after the stream is ignored.
     */
    let record_span = (1 + secondary_count as usize) * 32;

    let mut stream: Option<(u32, u64, u8)> = None;

    let mut name_units: Vec<u16> = Vec::new();

    if record_span <= buffer.len() {
        for index in 1..=secondary_count as usize {
            let slot = &buffer[index * 32..index * 32 + 32];

            let type_byte = slot[0];

            if type_byte == ENTRY_STREAM || type_byte == (ENTRY_STREAM & !IN_USE_BIT) {
                let cluster = read_u32(slot, 20);

                let data_length = read_u64(slot, 24);

                let stream_name_length = slot[3];

                stream = Some((cluster, data_length, stream_name_length));
            } else if type_byte == ENTRY_FILE_NAME || type_byte == (ENTRY_FILE_NAME & !IN_USE_BIT) {
                for pair in slot[2..32].chunks_exact(2) {
                    let unit = u16::from_le_bytes([pair[0], pair[1]]);

                    if unit == 0 {
                        break;
                    }

                    name_units.push(unit);
                }
            }
        }
    }

    let (cluster, size, stream_name_length) = match stream {
        Some((cluster, size, name_length)) => (cluster, size, name_length),
        None => (0, 0, name_length as u8),
    };

    /*
     * The length recorded in the file entry and the stream extension
     * is the number of UTF-16 characters. Prefer the stream value when
     * it looks valid, but never admit more units than the secondary
     * entries present in the record can actually hold.
     */
    let capacity = secondary_count as usize * NAME_UNITS_PER_ENTRY;

    /*
     * The file entry's NameLength is redundant with the stream's. The
     * Linux kernel leaves the file entry's field at zero and records
     * the authoritative length in the stream extension, so prefer the
     * stream value whenever it is non-zero.
     */
    let expected_length = if stream_name_length != 0 {
        stream_name_length as usize
    } else {
        name_length as usize
    };

    name_units.truncate(expected_length.min(capacity));

    let name = if name_units.is_empty() {
        if deleted {
            "?".to_string()
        } else {
            String::new()
        }
    } else {
        String::from_utf16_lossy(&name_units)
    };

    let kind = if attributes & ATTR_DIRECTORY != 0 {
        ExFatEntryKind::Directory
    } else {
        ExFatEntryKind::File
    };

    let created_at = decode_timestamp(read_u32(buffer, 8));

    let modified_at = decode_timestamp(read_u32(buffer, 12));

    let accessed_at = decode_timestamp(read_u32(buffer, 16));

    Some(ExFatDirectoryEntry::new(
        name,
        attributes,
        cluster,
        size,
        deleted,
        kind,
        secondary_count,
        created_at,
        modified_at,
        accessed_at,
    ))
}

/// Parses the volume label entry.
fn parse_volume_label(slot: &[u8]) -> Option<ExFatDirectoryEntry> {
    let character_count = slot[1] as usize;

    let mut units = Vec::new();

    for pair in slot[2..32].chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);

        if unit == 0 {
            break;
        }

        units.push(unit);
    }

    units.truncate(character_count);

    let name = String::from_utf16_lossy(&units);

    Some(ExFatDirectoryEntry::new(
        name,
        0,
        0,
        0,
        false,
        ExFatEntryKind::VolumeLabel,
        0,
        None,
        None,
        None,
    ))
}

/// Reads a little-endian u32 at `offset`.
fn read_u32(slot: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        slot[offset],
        slot[offset + 1],
        slot[offset + 2],
        slot[offset + 3],
    ])
}

/// Reads a little-endian u64 at `offset`.
fn read_u64(slot: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(slot[offset..offset + 8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_entry(deleted: bool, attributes: u8, secondary_count: u8) -> [u8; 32] {
        let mut slot = [0u8; 32];

        slot[0] = if deleted {
            ENTRY_FILE & !IN_USE_BIT
        } else {
            ENTRY_FILE
        };
        slot[1] = secondary_count;
        slot[4] = attributes;

        slot
    }

    fn stream_entry(deleted: bool, cluster: u32, size: u64, name_length: u8) -> [u8; 32] {
        let mut slot = [0u8; 32];

        slot[0] = if deleted {
            ENTRY_STREAM & !IN_USE_BIT
        } else {
            ENTRY_STREAM
        };
        slot[1] = 0x01; // AllocationPossible
        slot[3] = name_length;
        slot[20..24].copy_from_slice(&cluster.to_le_bytes());
        slot[24..32].copy_from_slice(&size.to_le_bytes());

        slot
    }

    fn name_entry(deleted: bool, name: &str) -> [u8; 32] {
        let mut slot = [0u8; 32];

        slot[0] = if deleted {
            ENTRY_FILE_NAME & !IN_USE_BIT
        } else {
            ENTRY_FILE_NAME
        };

        let mut units: Vec<u8> = name
            .encode_utf16()
            .collect::<Vec<u16>>()
            .into_iter()
            .flat_map(|unit| unit.to_le_bytes())
            .take(30)
            .collect();

        units.resize(30, 0);

        slot[2..32].copy_from_slice(&units);

        slot
    }

    fn plain_buffer(blocks: &[[u8; 32]]) -> Vec<u8> {
        blocks.iter().flatten().copied().collect()
    }

    #[test]
    fn parses_live_file_record() {
        let mut file = file_entry(false, 0x20, 2);
        file[28..30].copy_from_slice(&9u16.to_le_bytes());

        let blocks = [
            file,
            stream_entry(false, 42, 4096, 9),
            name_entry(false, "relatorio"),
        ];

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "relatorio");
        assert_eq!(entries[0].cluster(), 42);
        assert_eq!(entries[0].size(), 4096);
        assert!(!entries[0].is_deleted());
        assert_eq!(entries[0].kind(), ExFatEntryKind::File);
    }

    #[test]
    fn parses_multi_slot_name() {
        let name = "relatorio_final_do_projeto_2026.txt";

        let length = name.encode_utf16().count() as u16;

        let mut file = file_entry(false, 0x20, 4);
        file[28..30].copy_from_slice(&length.to_le_bytes());

        let mut stream = stream_entry(false, 7, 2048, length as u8);
        stream[3] = length as u8;

        let mut blocks = vec![file, stream];

        let units: Vec<u16> = name.encode_utf16().collect();

        for chunk in units.chunks(NAME_UNITS_PER_ENTRY) {
            let mut slot = [0u8; 32];
            slot[0] = ENTRY_FILE_NAME;
            for (index, unit) in chunk.iter().enumerate() {
                let target = 2 + index * 2;
                slot[target] = (unit & 0xFF) as u8;
                slot[target + 1] = (unit >> 8) as u8;
            }
            blocks.push(slot);
        }

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), name);
    }

    #[test]
    fn parses_volume_label() {
        let mut slot = [0u8; 32];
        slot[0] = ENTRY_VOLUME_LABEL;
        slot[1] = 7;
        let label_units: Vec<u8> = "EVID008"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        slot[2..2 + label_units.len()].copy_from_slice(&label_units);

        let entries = parse_directory_entries(&plain_buffer(&[slot]));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "EVID008");
        assert!(entries[0].is_volume_label());
    }

    #[test]
    fn deleted_record_keeps_name_and_chain() {
        let mut file = file_entry(true, 0x20, 2);
        file[28..30].copy_from_slice(&7u16.to_le_bytes());

        let blocks = [
            file,
            stream_entry(true, 99, 512, 7),
            name_entry(true, "apagado"),
        ];

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "apagado");
        assert!(entries[0].is_deleted());
        assert_eq!(entries[0].cluster(), 99);
        assert_eq!(entries[0].size(), 512);
    }

    #[test]
    fn deleted_without_name_gets_placeholder() {
        let mut file = file_entry(true, 0x20, 1);
        file[28..30].copy_from_slice(&8u16.to_le_bytes());

        let blocks = [file, stream_entry(true, 101, 1024, 8)];

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "?");
        assert!(entries[0].is_deleted());
    }

    #[test]
    fn directory_entry_is_detected() {
        let mut file = file_entry(false, 0x10, 2);
        file[28..30].copy_from_slice(&4u16.to_le_bytes());

        let blocks = [
            file,
            stream_entry(false, 60, 0, 4),
            name_entry(false, "dir1"),
        ];

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_directory());
    }

    #[test]
    fn stops_at_end_mark() {
        let mut file = file_entry(false, 0x20, 2);
        file[28..30].copy_from_slice(&5u16.to_le_bytes());

        let blocks = [
            file,
            stream_entry(false, 3, 5, 5),
            name_entry(false, "vivo"),
        ];

        let mut buffer = plain_buffer(&blocks);
        buffer.extend_from_slice(&[END_MARK; 32]);
        buffer.extend_from_slice(&[0u8; 64]);

        let entries = parse_directory_entries(&buffer);

        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn decodes_timestamp() {
        // 2026-01-02 03:04:06 encoded as date/time.
        let year_2026 = 2026 - 1980;
        let date = (year_2026 << 9) | (1 << 5) | 2;
        let time = (3 << 11) | (4 << 5) | 3; // 6 seconds = 3 half-seconds

        let raw = (date << 16) | time;

        let decoded = decode_timestamp(raw).unwrap();

        assert_eq!(decoded.timestamp(), 1767323046);
    }

    #[test]
    fn zero_timestamp_returns_none() {
        assert_eq!(decode_timestamp(0), None);
    }
}

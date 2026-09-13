//! FAT32 directory entry parsing.
//!
//! FAT32 directories are plain sequences of 32-byte slots. A regular
//! entry carries the classic 8.3 name; long file names are stored in
//! one or more Long File Name (LFN) slots placed immediately before it.
//!
//! Deleting a file only overwrites the first byte of the short entry
//! with `0xE5`, which keeps both the cluster chain and, usually, the
//! LFN slots recoverable.

/// Read-only attribute bit.
pub const ATTR_READ_ONLY: u8 = 0x01;

/// Hidden attribute bit.
pub const ATTR_HIDDEN: u8 = 0x02;

/// System attribute bit.
pub const ATTR_SYSTEM: u8 = 0x04;

/// Volume label attribute bit.
pub const ATTR_VOLUME_LABEL: u8 = 0x08;

/// Directory attribute bit.
pub const ATTR_DIRECTORY: u8 = 0x10;

/// Archive attribute bit.
pub const ATTR_ARCHIVE: u8 = 0x20;

/// Long file name slot attribute.
pub const ATTR_LONG_NAME: u8 = 0x0F;

/// First byte value used to mark a deleted entry.
const DELETED_FIRST_BYTE: u8 = 0xE5;

/// First byte value marking the end of a directory.
const END_MARK: u8 = 0x00;

/// Maximum number of UTF-16 units stored in a single LFN slot.
const LFN_UNITS_PER_SLOT: usize = 13;

/// One fully resolved FAT32 directory entry.
#[derive(Debug, Clone)]
pub struct Fat32DirectoryEntry {
    name: String,
    short_name: Option<String>,
    attributes: u8,
    cluster: u32,
    size: u32,
    deleted: bool,
}

impl Fat32DirectoryEntry {
    /// Creates a directory entry.
    fn new(
        name: String,
        short_name: Option<String>,
        attributes: u8,
        cluster: u32,
        size: u32,
        deleted: bool,
    ) -> Self {
        Self {
            name,
            short_name,
            attributes,
            cluster,
            size,
            deleted,
        }
    }

    /// Returns the displayed name (LFN when available, 8.3 otherwise).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the short 8.3 name when one was stored.
    pub fn short_name(&self) -> Option<&str> {
        self.short_name.as_deref()
    }

    /// Returns the raw attribute byte.
    pub fn attributes(&self) -> u8 {
        self.attributes
    }

    /// Returns the starting cluster number.
    pub fn cluster(&self) -> u32 {
        self.cluster
    }

    /// Returns the file size in bytes (zero for directories).
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Returns true when the entry has been deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Returns true when the entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }

    /// Returns true when the entry is a volume label.
    pub fn is_volume_label(&self) -> bool {
        self.attributes & ATTR_VOLUME_LABEL != 0
    }

    /// Returns true when the entry carries the hidden attribute.
    pub fn is_hidden(&self) -> bool {
        self.attributes & ATTR_HIDDEN != 0
    }

    /// Returns true when the entry carries the read-only attribute.
    pub fn is_read_only(&self) -> bool {
        self.attributes & ATTR_READ_ONLY != 0
    }

    /// Returns true when the entry carries the system attribute.
    pub fn is_system(&self) -> bool {
        self.attributes & ATTR_SYSTEM != 0
    }
}

/// Computes the checksum used to tie LFN slots to their 8.3 entry.
pub fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut checksum = 0u8;

    for byte in short_name {
        checksum = ((checksum & 1) << 7) | (checksum >> 1);
        checksum = checksum.wrapping_add(*byte);
    }

    checksum
}

/// Decodes one 8.3 name field (name or extension) into a display string.
///
/// Trailing spaces and null bytes are trimmed. Non-printable bytes are
/// kept as their code point for a raw, lossless representation.
fn decode_short_component(bytes: &[u8]) -> String {
    let mut name = String::new();

    for byte in bytes {
        if *byte == 0x00 || *byte == b' ' {
            break;
        }

        name.push(char::from(*byte));
    }

    name
}

/// Builds the classic 8.3 display name from the 11 raw bytes.
pub fn short_name_from_bytes(bytes: &[u8; 11]) -> String {
    let name = decode_short_component(&bytes[..8]);
    let ext = decode_short_component(&bytes[8..]);

    if ext.is_empty() {
        name
    } else if name.is_empty() {
        format!(".{ext}")
    } else {
        format!("{name}.{ext}")
    }
}

/// Decodes the UTF-16 units stored in one LFN slot.
///
/// One slot carries 13 UTF-16 units split across three areas: five
/// units, six units and two units. Returns the units without the
/// trailing padding (`0xFFFF`) and terminator (`0x0000`) markers.
fn lfn_slot_units(slot: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(LFN_UNITS_PER_SLOT);

    for range in [0x01..0x0B, 0x0E..0x1A, 0x1C..0x20] {
        for pair in slot[range].chunks_exact(2) {
            let value = u16::from_le_bytes([pair[0], pair[1]]);

            if value == 0xFFFF || value == 0x0000 {
                break;
            }

            units.push(value);
        }
    }

    units
}

/// Returns true when the display name is a plausible FAT leaf name.
///
/// A real directory entry carries a printable name (ASCII graphic plus
/// normally-encoded UTF-16). When the fingerprinted name is mostly
/// binary — the signature of a damaged or recycled directory cluster
/// being read as if it were a valid slot sequence — the entry is
/// discarded instead of polluting the laudo with false positives.
pub fn is_plausible_leaf_name(name: &str) -> bool {
    if name.is_empty() || name.chars().any(|c| c == '\0') {
        return false;
    }

    let mut printable = 0u64;
    let mut total = 0u64;
    for c in name.chars() {
        total += 1;
        if !c.is_control() && !c.is_whitespace() {
            printable += 1;
        }
    }
    printable as f64 / total as f64 >= 0.7
}

/// Parses all directory slots contained in `buffer`.
///
/// The function stops at the first zero entry (directory end). Deleted
/// entries are returned together with their best-effort LFN name when
/// the residual LFN slots are still present.
pub fn parse_directory_entries(buffer: &[u8]) -> Vec<Fat32DirectoryEntry> {
    let mut entries = Vec::new();

    let mut lfn_units: Vec<u16> = Vec::new();

    let mut lfn_has_pending = false;

    let mut offset = 0usize;

    while offset + 32 <= buffer.len() {
        let slot = &buffer[offset..offset + 32];

        let first = slot[0];

        if first == END_MARK {
            break;
        }

        if slot[0x0B] == ATTR_LONG_NAME {
            lfn_units.extend(lfn_slot_units(slot));

            lfn_has_pending = true;
        } else {
            let name = build_leaf_name(slot, &lfn_units, lfn_has_pending);

            if !is_plausible_leaf_name(&name) {
                lfn_units.clear();
                lfn_has_pending = false;
                continue;
            }

            append_leaf_entry(&mut entries, slot, name);

            lfn_units.clear();
            lfn_has_pending = false;
        }

        offset += 32;
    }

    entries
}

/// Builds the display name of a non-LFN slot.
///
/// The LFN suffix is accepted when it belongs to the same file: either
/// the checksum stored in the LFN slots matches the short entry, or the
/// short entry was deleted (the first byte is gone, so the checksum can
/// no longer be verified and the adjacent LFN slots are used as a
/// best-effort reconstruction).
fn build_leaf_name(slot: &[u8], lfn_units: &[u16], lfn_has_pending: bool) -> String {
    let short = extract_short_name(slot);

    let deleted = slot[0] == DELETED_FIRST_BYTE;

    let checksum_matches = lfn_checksum(&short) == slot[0x0D];

    if lfn_has_pending && (checksum_matches || deleted) {
        String::from_utf16_lossy(lfn_units)
    } else {
        short_name_with_placeholder(&short, deleted)
    }
}

/// Copies the 11 raw name bytes, restoring the deleted first byte into
/// a placeholder so the checksum computation stays well-defined.
fn extract_short_name(slot: &[u8]) -> [u8; 11] {
    let mut short = [0u8; 11];

    short.copy_from_slice(&slot[0..11]);

    short
}

/// Builds the 8.3 name, replacing the deleted marker with '?'.
fn short_name_with_placeholder(short: &[u8; 11], deleted: bool) -> String {
    let mut bytes = *short;

    if deleted {
        bytes[0] = b'?';
    }

    short_name_from_bytes(&bytes)
}

/// Decodes an 11-byte volume label without applying the 8.3 split.
fn short_name_from_volume_label(bytes: &[u8; 11]) -> String {
    let mut name = String::new();

    for byte in bytes {
        if *byte == 0x00 || *byte == b' ' {
            break;
        }

        name.push(char::from(*byte));
    }

    name
}

/// Appends a leaf (short) entry to the result vector.
fn append_leaf_entry(entries: &mut Vec<Fat32DirectoryEntry>, slot: &[u8], name: String) {
    if slot[0] == b'.' {
        // The "." and ".." entries are not real findings.
        return;
    }

    let attributes = slot[0x0B];

    if attributes & ATTR_VOLUME_LABEL != 0 {
        // Volume labels are not 8.3 entries: the full 11 bytes form
        // a single text field.
        let label = short_name_from_volume_label(&extract_short_name(slot));

        entries.push(Fat32DirectoryEntry::new(
            label, None, attributes, 0, 0, false,
        ));

        return;
    }

    let cluster_high = u16::from_le_bytes([slot[0x14], slot[0x15]]);

    let cluster_low = u16::from_le_bytes([slot[0x1A], slot[0x1B]]);

    let cluster = (u32::from(cluster_high) << 16) | u32::from(cluster_low);

    let size = u32::from_le_bytes(slot[0x1C..0x20].try_into().expect("size is 4 bytes"));

    let short = Some(short_name_from_bytes(&extract_short_name(slot)));

    entries.push(Fat32DirectoryEntry::new(
        name,
        short,
        attributes,
        cluster,
        size,
        slot[0] == DELETED_FIRST_BYTE,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short_entry(name: [u8; 11], attributes: u8, cluster: u32, size: u32) -> [u8; 32] {
        let mut slot = [0u8; 32];

        slot[0..11].copy_from_slice(&name);
        slot[0x0B] = attributes;
        slot[0x0D] = lfn_checksum(&name);
        slot[0x14] = ((cluster >> 16) & 0xFF) as u8;
        slot[0x15] = ((cluster >> 24) & 0xFF) as u8;
        slot[0x1A] = (cluster & 0xFF) as u8;
        slot[0x1B] = ((cluster >> 8) & 0xFF) as u8;
        slot[0x1C..0x20].copy_from_slice(&size.to_le_bytes());

        slot
    }

    fn lfn_blocks(name: &str, short_name: [u8; 11]) -> Vec<[u8; 32]> {
        let units: Vec<u16> = name.encode_utf16().collect();

        let checksum = lfn_checksum(&short_name);

        let mut blocks = Vec::new();

        let mut chunk_start = 0usize;

        for ordinal in (1..=99u8).rev() {
            let chunk: Vec<u16> = units
                .iter()
                .skip(chunk_start)
                .cloned()
                .take(LFN_UNITS_PER_SLOT)
                .collect();

            if chunk.is_empty() {
                break;
            }

            let mut bytes = Vec::new();
            for unit in &chunk {
                bytes.push((unit & 0xFF) as u8);
                bytes.push((unit >> 8) as u8);
            }
            while bytes.len() < 26 {
                bytes.push(0xFF);
                bytes.push(0xFF);
            }

            let mut slot = [0u8; 32];
            slot[0] = 0x40 | ordinal;
            slot[0x0B] = ATTR_LONG_NAME;
            slot[0x0D] = checksum;

            let mut target = [0u8; 10];
            target.copy_from_slice(&bytes[0..10]);
            slot[0x01..0x0B].copy_from_slice(&target);

            let mut target = [0u8; 12];
            target.copy_from_slice(&bytes[10..22]);
            slot[0x0E..0x1A].copy_from_slice(&target);

            let mut target = [0u8; 4];
            target.copy_from_slice(&bytes[22..26]);
            slot[0x1C..0x20].copy_from_slice(&target);

            blocks.push(slot);

            chunk_start += chunk.len();

            if chunk_start >= units.len() {
                break;
            }
        }

        blocks
    }

    fn plain_buffer(blocks: &[[u8; 32]]) -> Vec<u8> {
        blocks.iter().flatten().copied().collect()
    }

    #[test]
    fn parses_short_name_entry() {
        let mut name = [b' '; 11];
        name[..8].copy_from_slice(b"ARQUIVO ");
        name[8..11].copy_from_slice(b"TXT");

        let block = short_entry(name, ATTR_ARCHIVE, 42, 4096);

        let entries = parse_directory_entries(&plain_buffer(&[block]));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "ARQUIVO.TXT");
        assert_eq!(entries[0].cluster(), 42);
        assert_eq!(entries[0].size(), 4096);
        assert!(!entries[0].is_deleted());
    }

    #[test]
    fn stops_at_directory_end() {
        let mut name = [b' '; 11];
        name[..8].copy_from_slice(b"FILE    ");

        let mut buffer = plain_buffer(&[short_entry(name, ATTR_ARCHIVE, 2, 0)]);
        buffer.extend_from_slice(&[0u8; 64]);

        let entries = parse_directory_entries(&buffer);

        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn reassembles_long_file_name() {
        let short = {
            let mut name = [b' '; 11];
            name[..8].copy_from_slice(b"RELATO~1");
            name[8..11].copy_from_slice(b"PDF");
            name
        };

        let long = "relatorio_final_de_projeto_2026.pdf";

        let mut blocks = lfn_blocks(long, short);
        blocks.push(short_entry(short, ATTR_ARCHIVE, 7, 2048));

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), long);
        assert_eq!(entries[0].short_name(), Some("RELATO~1.PDF"));
    }

    #[test]
    fn long_name_with_single_slot() {
        let short = {
            let mut name = [b' '; 11];
            name[..8].copy_from_slice(b"PEQUEN~1");
            name[8..11].copy_from_slice(b"TXT");
            name
        };

        let long = "curto.txt";

        let mut blocks = lfn_blocks(long, short);
        blocks.push(short_entry(short, ATTR_ARCHIVE, 9, 100));

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries[0].name(), long);
    }

    #[test]
    fn deleted_entry_keeps_lfn_residual() {
        let short = {
            let mut name = [b' '; 11];
            name[..8].copy_from_slice(b"APAGAD~1");
            name[8..11].copy_from_slice(b"TXT");
            name
        };

        let long = "nota_de_investigacao_confidencial.txt";

        let mut blocks = lfn_blocks(long, short);
        blocks[0][0] = DELETED_FIRST_BYTE;

        let mut short_block = short_entry(short, ATTR_ARCHIVE, 5, 512);
        short_block[0] = DELETED_FIRST_BYTE;
        blocks.push(short_block);

        let entries = parse_directory_entries(&plain_buffer(&blocks));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), long);
        assert!(entries[0].is_deleted());
    }

    #[test]
    fn parses_volume_label() {
        let mut name = [b' '; 11];
        name[..10].copy_from_slice(b"EVIDENCIA1");
        name[10] = b' ';

        let block = short_entry(name, ATTR_VOLUME_LABEL, 0, 0);

        let entries = parse_directory_entries(&plain_buffer(&[block]));

        assert_eq!(entries[0].name(), "EVIDENCIA1");
        assert!(entries[0].is_volume_label());
    }

    #[test]
    fn deleted_without_lfn_gets_placeholder() {
        let mut name = [b' '; 11];
        name[..8].copy_from_slice(b"ARQ     ");
        name[8..11].copy_from_slice(b"BIN");

        let mut block = short_entry(name, ATTR_ARCHIVE, 3, 2048);
        block[0] = DELETED_FIRST_BYTE;

        let entries = parse_directory_entries(&plain_buffer(&[block]));

        assert_eq!(entries[0].name(), "?RQ.BIN");
        assert!(entries[0].is_deleted());
    }

    #[test]
    fn skips_dot_entries() {
        let dot = short_entry(*b".          ", ATTR_DIRECTORY, 2, 0);
        let dotdot = short_entry(*b"..         ", ATTR_DIRECTORY, 2, 0);

        let entries = parse_directory_entries(&plain_buffer(&[dot, dotdot]));

        assert!(entries.is_empty());
    }

    #[test]
    fn computes_stable_checksum() {
        let mut name = [b' '; 11];
        name[..8].copy_from_slice(b"TEST    ");
        name[8..11].copy_from_slice(b"TXT");

        let a = lfn_checksum(&name);
        let b = lfn_checksum(&name);

        assert_eq!(a, b);
    }

    #[test]
    fn lfn_checksum_is_order_sensitive() {
        let mut name_a = [b' '; 11];
        name_a[..8].copy_from_slice(b"ABCDEFG ");
        let mut name_b = [b' '; 11];
        name_b[..8].copy_from_slice(b"GFEDCBA ");
        name_b[8..11].copy_from_slice(b"TXT");
        name_a[8..11].copy_from_slice(b"TXT");

        assert_ne!(lfn_checksum(&name_a), lfn_checksum(&name_b));
    }
}

use forensis_core::filesystem::ext4::Ext4DirectoryEntry;

fn build_entry(
    inode: u32,
    record_length: u16,
    name: &[u8],
    file_type: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; record_length as usize];

    data[0..4].copy_from_slice(&inode.to_le_bytes());
    data[4..6].copy_from_slice(&record_length.to_le_bytes());
    data[6] = name.len() as u8;
    data[7] = file_type;

    data[8..8 + name.len()].copy_from_slice(name);

    data
}

#[test]
fn parses_valid_directory_entry() {
    let data = build_entry(12, 16, b"arquivo", 1);

    let entry = Ext4DirectoryEntry::parse(&data).unwrap();

    assert_eq!(entry.inode(), 12);
    assert_eq!(entry.record_length(), 16);
    assert_eq!(entry.name_length(), 7);
    assert_eq!(entry.file_type(), 1);
    assert_eq!(entry.name(), "arquivo");
}

#[test]
fn rejects_insufficient_header() {
    let data = [0u8; 7];

    let result = Ext4DirectoryEntry::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_record_length_smaller_than_header() {
    let mut data = [0u8; 8];

    data[4..6].copy_from_slice(&7u16.to_le_bytes());

    let result = Ext4DirectoryEntry::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_name_larger_than_record() {
    let mut data = [0u8; 12];

    data[4..6].copy_from_slice(&12u16.to_le_bytes());
    data[6] = 5;

    let result = Ext4DirectoryEntry::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_truncated_name() {
    let mut data = [0u8; 8];

    data[4..6].copy_from_slice(&16u16.to_le_bytes());
    data[6] = 4;

    let result = Ext4DirectoryEntry::parse(&data);

    assert!(result.is_err());
}

#[test]
fn identifies_unused_entry() {
    let data = build_entry(0, 16, b"unused", 0);

    let entry = Ext4DirectoryEntry::parse(&data).unwrap();

    assert!(entry.is_unused());
}

#[test]
fn identifies_regular_file() {
    let data = build_entry(15, 16, b"file", 1);

    let entry = Ext4DirectoryEntry::parse(&data).unwrap();

    assert!(entry.is_regular_file());
    assert!(!entry.is_directory());
    assert!(!entry.is_symlink());
}

#[test]
fn identifies_directory() {
    let data = build_entry(20, 16, b"dir", 2);

    let entry = Ext4DirectoryEntry::parse(&data).unwrap();

    assert!(entry.is_directory());
    assert!(!entry.is_regular_file());
    assert!(!entry.is_symlink());
}

#[test]
fn identifies_symbolic_link() {
    let data = build_entry(25, 16, b"link", 7);

    let entry = Ext4DirectoryEntry::parse(&data).unwrap();

    assert!(entry.is_symlink());
    assert!(!entry.is_regular_file());
    assert!(!entry.is_directory());
}

#[test]
fn parses_multiple_entries_in_block() {
    let first = build_entry(12, 16, b"file", 1);
    let second = build_entry(13, 16, b"docs", 2);

    let mut block = Vec::new();
    block.extend_from_slice(&first);
    block.extend_from_slice(&second);

    let entries = Ext4DirectoryEntry::parse_block(&block).unwrap();

    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].inode(), 12);
    assert_eq!(entries[0].name(), "file");

    assert_eq!(entries[1].inode(), 13);
    assert_eq!(entries[1].name(), "docs");
}

#[test]
fn stops_at_zero_record_length() {
    let first = build_entry(12, 16, b"file", 1);
    let mut block = first;

    block.extend_from_slice(&[0u8; 16]);

    let entries = Ext4DirectoryEntry::parse_block(&block).unwrap();

    assert_eq!(entries.len(), 1);
}

#[test]
fn rejects_entry_smaller_than_header_in_block() {
    let mut block = vec![0u8; 8];

    block[4..6].copy_from_slice(&7u16.to_le_bytes());

    let result = Ext4DirectoryEntry::parse_block(&block);

    assert!(result.is_err());
}

#[test]
fn rejects_entry_crossing_block_boundary() {
    let mut block = vec![0u8; 16];

    block[4..6].copy_from_slice(&32u16.to_le_bytes());

    let result = Ext4DirectoryEntry::parse_block(&block);

    assert!(result.is_err());
}

#[test]
fn accepts_trailing_bytes_smaller_than_header() {
    let entry = build_entry(12, 16, b"file", 1);

    let mut block = entry;
    block.extend_from_slice(&[0u8; 4]);

    let entries = Ext4DirectoryEntry::parse_block(&block).unwrap();

    assert_eq!(entries.len(), 1);
}

#[test]
fn handles_invalid_utf8_filename() {
    let mut data = build_entry(12, 16, &[0xFF, 0xFE], 1);

    data[6] = 2;

    let result = Ext4DirectoryEntry::parse(&data);

    assert!(result.is_ok());

    let entry = result.unwrap();

    assert_eq!(entry.inode(), 12);
    assert_eq!(entry.name_length(), 2);
}

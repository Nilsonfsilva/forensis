use forensis_core::filesystem::{IndexEntry, NtfsDirectoryEntry};

#[test]
fn test_create_directory_entry_from_index_entry() {
    let file_name_data = create_file_name_value("evidence.txt", 5, 100, 80, 0x20);

    let entry_length = 16 + file_name_data.len();

    let mut entry_data = vec![0u8; entry_length];

    // ---------------------------------------------------------
    // INDEX_ENTRY
    // ---------------------------------------------------------

    // MFT file reference
    entry_data[0..8].copy_from_slice(&42u64.to_le_bytes());

    // Entry length
    entry_data[8..10].copy_from_slice(&(entry_length as u16).to_le_bytes());

    // Key length
    entry_data[10..12].copy_from_slice(&(file_name_data.len() as u16).to_le_bytes());

    // Flags
    entry_data[12..14].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // FILE_NAME
    // ---------------------------------------------------------

    entry_data[16..].copy_from_slice(&file_name_data);

    // ---------------------------------------------------------
    // PARSE INDEX_ENTRY
    // ---------------------------------------------------------

    let entry = IndexEntry::parse(&entry_data).expect("INDEX_ENTRY should be valid");

    // ---------------------------------------------------------
    // CREATE DIRECTORY ENTRY
    // ---------------------------------------------------------

    let directory_entry =
        NtfsDirectoryEntry::from_index_entry(&entry).expect("Directory entry should be valid");

    // ---------------------------------------------------------
    // VALIDATE
    // ---------------------------------------------------------

    assert_eq!(directory_entry.file_reference, 42);

    assert_eq!(directory_entry.name(), "evidence.txt");

    assert_eq!(directory_entry.parent_reference(), 5);

    assert_eq!(directory_entry.file_name.allocated_size, 100);

    assert_eq!(directory_entry.file_name.real_size, 80);

    assert!(directory_entry.is_file());

    assert!(!directory_entry.is_directory());
}

#[test]
fn test_directory_entry_rejects_empty_key() {
    let entry = IndexEntry {
        file_reference: 42,
        entry_length: 16,
        key_length: 0,
        flags: 0,
        key: Vec::new(),
    };

    let result = NtfsDirectoryEntry::from_index_entry(&entry);

    assert!(result.is_err());
}

#[test]
fn test_directory_entry_detects_directory() {
    let file_name_data = create_file_name_value("documents", 5, 0, 0, 0x10000000);

    let entry_length = 16 + file_name_data.len();

    let mut entry_data = vec![0u8; entry_length];

    // MFT file reference
    entry_data[0..8].copy_from_slice(&100u64.to_le_bytes());

    // Entry length
    entry_data[8..10].copy_from_slice(&(entry_length as u16).to_le_bytes());

    // Key length
    entry_data[10..12].copy_from_slice(&(file_name_data.len() as u16).to_le_bytes());

    // Flags
    entry_data[12..14].copy_from_slice(&0u16.to_le_bytes());

    // FILE_NAME as key
    entry_data[16..].copy_from_slice(&file_name_data);

    let entry = IndexEntry::parse(&entry_data).expect("INDEX_ENTRY should be valid");

    let directory_entry =
        NtfsDirectoryEntry::from_index_entry(&entry).expect("Directory entry should be valid");

    assert_eq!(directory_entry.file_reference, 100);

    assert_eq!(directory_entry.name(), "documents");

    assert!(directory_entry.is_directory());

    assert!(!directory_entry.is_file());
}

fn create_file_name_value(
    name: &str,
    parent_reference: u64,
    allocated_size: u64,
    real_size: u64,
    flags: u32,
) -> Vec<u8> {
    let utf16_name = name.encode_utf16().collect::<Vec<u16>>();

    let mut data = vec![0u8; 66 + utf16_name.len() * 2];

    // Parent directory MFT reference
    data[0..8].copy_from_slice(&parent_reference.to_le_bytes());

    // Allocated file size
    data[40..48].copy_from_slice(&allocated_size.to_le_bytes());

    // Real file size
    data[48..56].copy_from_slice(&real_size.to_le_bytes());

    // File flags
    data[56..60].copy_from_slice(&flags.to_le_bytes());

    // File name length
    data[64] = utf16_name.len() as u8;

    // Namespace
    data[65] = 1;

    // UTF-16 file name
    for (index, character) in utf16_name.iter().enumerate() {
        let offset = 66 + index * 2;

        data[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }

    data
}

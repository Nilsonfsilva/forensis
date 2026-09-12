use forensis_core::filesystem::IndexEntry;

#[test]
fn test_index_entry_parses_file_name_key() {
    // ---------------------------------------------------------
    // FILE_NAME
    // ---------------------------------------------------------

    let name = "documento.txt";

    let utf16: Vec<u16> = name.encode_utf16().collect();

    let file_name_size = 66 + utf16.len() * 2;

    // INDEX_ENTRY header = 16 bytes.
    let entry_length = 16 + file_name_size;

    let mut data = vec![0u8; entry_length];

    // ---------------------------------------------------------
    // INDEX_ENTRY HEADER
    // ---------------------------------------------------------

    // MFT file reference.
    data[0..8].copy_from_slice(&42u64.to_le_bytes());

    // INDEX_ENTRY length.
    data[8..10].copy_from_slice(&(entry_length as u16).to_le_bytes());

    // Key length.
    data[10..12].copy_from_slice(&(file_name_size as u16).to_le_bytes());

    // Flags.
    data[12..14].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // FILE_NAME ATTRIBUTE
    // ---------------------------------------------------------

    let key = 16usize;

    // Parent directory MFT reference.
    data[key..key + 8].copy_from_slice(&5u64.to_le_bytes());

    // Allocated file size.
    data[key + 40..key + 48].copy_from_slice(&4096u64.to_le_bytes());

    // Real file size.
    data[key + 48..key + 56].copy_from_slice(&1234u64.to_le_bytes());

    // File attributes.
    data[key + 56..key + 60].copy_from_slice(&0x20u32.to_le_bytes());

    // File name length.
    data[key + 64] = utf16.len() as u8;

    // Namespace = Win32.
    data[key + 65] = 1u8;

    // ---------------------------------------------------------
    // UTF-16 FILE_NAME
    // ---------------------------------------------------------

    for (index, character) in utf16.iter().enumerate() {
        let offset = key + 66 + index * 2;

        data[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }

    // ---------------------------------------------------------
    // PARSE INDEX_ENTRY
    // ---------------------------------------------------------

    let entry = IndexEntry::parse(&data).expect("INDEX_ENTRY should be valid");

    assert_eq!(entry.file_reference, 42);

    assert_eq!(entry.key_length as usize, file_name_size);

    // ---------------------------------------------------------
    // PARSE FILE_NAME FROM INDEX_ENTRY
    // ---------------------------------------------------------

    let file_name = entry.file_name().expect("FILE_NAME should be valid");

    // ---------------------------------------------------------
    // VALIDATE FILE_NAME
    // ---------------------------------------------------------

    assert_eq!(file_name.parent_record, 5);

    assert_eq!(file_name.allocated_size, 4096);

    assert_eq!(file_name.real_size, 1234);

    assert_eq!(file_name.file_attributes, 0x20);

    assert_eq!(file_name.name, "documento.txt");
}

#[test]
fn test_index_entry_rejects_empty_file_name_key() {
    let mut data = vec![0u8; 16];

    // MFT file reference.
    data[0..8].copy_from_slice(&42u64.to_le_bytes());

    // INDEX_ENTRY length.
    data[8..10].copy_from_slice(&16u16.to_le_bytes());

    // Key length = zero.
    data[10..12].copy_from_slice(&0u16.to_le_bytes());

    // Flags.
    data[12..14].copy_from_slice(&0u16.to_le_bytes());

    let entry = IndexEntry::parse(&data).expect("INDEX_ENTRY should be valid");

    let result = entry.file_name();

    assert!(result.is_err());
}

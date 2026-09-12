use forensis_core::filesystem::{IndexEntry, NtfsDirectory};

#[test]
fn test_index_entry_can_reference_file_name() {
    let key = create_file_name_value("arquivo.txt");

    let key_length = key.len() as u16;

    let entry = IndexEntry {
        file_reference: 42,

        entry_length: 16 + key_length,

        key_length,

        flags: 0,

        key,
    };

    let file_name = entry.file_name().expect("FILE_NAME should be valid");

    assert_eq!(entry.file_reference, 42);

    assert_eq!(file_name.name, "arquivo.txt");
}

#[test]
fn test_directory_returns_file_name_from_entry() {
    let key = create_file_name_value("arquivo.txt");

    let key_length = key.len() as u16;

    let entry = IndexEntry {
        file_reference: 42,

        entry_length: 16 + key_length,

        key_length,

        flags: 0,

        key,
    };

    let directory = NtfsDirectory {
        mft_record: 5,

        entries: vec![entry],
    };

    let file_name = directory
        .file_name(0)
        .expect("Directory FILE_NAME should be valid");

    assert_eq!(file_name.name, "arquivo.txt");
}

#[test]
fn test_directory_rejects_invalid_entry_index() {
    let key = create_file_name_value("arquivo.txt");

    let key_length = key.len() as u16;

    let entry = IndexEntry {
        file_reference: 42,

        entry_length: 16 + key_length,

        key_length,

        flags: 0,

        key,
    };

    let directory = NtfsDirectory {
        mft_record: 5,

        entries: vec![entry],
    };

    let result = directory.file_name(1);

    assert!(result.is_err());
}

#[test]
fn test_directory_returns_all_file_names() {
    let key_one = create_file_name_value("arquivo.txt");

    let key_one_length = key_one.len() as u16;

    let entry_one = IndexEntry {
        file_reference: 42,

        entry_length: 16 + key_one_length,

        key_length: key_one_length,

        flags: 0,

        key: key_one,
    };

    let key_two = create_file_name_value("foto.jpg");

    let key_two_length = key_two.len() as u16;

    let entry_two = IndexEntry {
        file_reference: 43,

        entry_length: 16 + key_two_length,

        key_length: key_two_length,

        flags: 0,

        key: key_two,
    };

    let directory = NtfsDirectory {
        mft_record: 5,

        entries: vec![entry_one, entry_two],
    };

    let names = directory
        .file_names()
        .expect("Directory FILE_NAME entries should be valid");

    assert_eq!(names.len(), 2);

    assert_eq!(names[0].name, "arquivo.txt");

    assert_eq!(names[1].name, "foto.jpg");
}

fn create_file_name_value(name: &str) -> Vec<u8> {
    let utf16: Vec<u16> = name.encode_utf16().collect();

    let mut data = vec![0u8; 66 + utf16.len() * 2];

    // ---------------------------------------------------------
    // Parent MFT file reference
    // ---------------------------------------------------------

    data[0..8].copy_from_slice(&5u64.to_le_bytes());

    // ---------------------------------------------------------
    // Allocated size
    // ---------------------------------------------------------

    data[40..48].copy_from_slice(&100u64.to_le_bytes());

    // ---------------------------------------------------------
    // Real size
    // ---------------------------------------------------------

    data[48..56].copy_from_slice(&80u64.to_le_bytes());

    // ---------------------------------------------------------
    // File attributes
    // ---------------------------------------------------------

    data[56..60].copy_from_slice(&0x20u32.to_le_bytes());

    // ---------------------------------------------------------
    // Filename length
    // ---------------------------------------------------------

    data[64] = utf16.len() as u8;

    // ---------------------------------------------------------
    // Namespace = Win32
    // ---------------------------------------------------------

    data[65] = 1;

    // ---------------------------------------------------------
    // UTF-16LE filename
    // ---------------------------------------------------------

    for (index, character) in utf16.iter().enumerate() {
        let offset = 66 + index * 2;

        data[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }

    data
}

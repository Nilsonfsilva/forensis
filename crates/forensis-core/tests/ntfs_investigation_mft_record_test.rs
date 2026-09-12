use forensis_core::filesystem::ntfs::{FileNameAttribute, Investigation, ParsedMftRecord};

#[test]
fn test_add_mft_record_to_investigation() {
    let file_name = FileNameAttribute {
        parent_record: 5,
        parent_sequence: 1,
        namespace: 1,
        name: "documento.txt".to_string(),
        allocated_size: 4096,
        real_size: 1234,
        file_attributes: 0x00000000,
    };

    let record = ParsedMftRecord {
        index: 42,
        mft_flags: 0x0001,
        standard_information: None,
        file_names: vec![file_name],
        data: None,
        index_root: None,
    };

    let mut investigation = Investigation::new(8);

    investigation.add_mft_record(&record);

    assert_eq!(investigation.entry_count(), 1);

    let entry = &investigation.entries()[0];

    assert_eq!(entry.mft_record, 42);

    assert_eq!(entry.name, "documento.txt");

    assert_eq!(entry.parent_mft_record, 5);

    assert_eq!(entry.allocated_size, 4096);

    assert_eq!(entry.real_size, 1234);

    assert!(!entry.is_directory);
}

use forensis_core::filesystem::{DataAttribute, FileNameAttribute, InvestigationEntry};
use forensis_core::forensic::model::ForensicContentSource;

#[test]
fn test_create_investigation_entry_from_file_name() {
    let file_name = FileNameAttribute {
        parent_record: 5,
        parent_sequence: 1,
        namespace: 1,
        allocated_size: 4096,
        real_size: 1024,
        file_attributes: 0x20,
        name: "arquivo.txt".to_string(),
    };

    let entry = InvestigationEntry::from_file_name(42, &file_name);

    assert_eq!(entry.mft_record, 42);

    assert_eq!(entry.parent_mft_record, 5);

    assert_eq!(entry.name, "arquivo.txt");

    assert_eq!(entry.allocated_size, 4096);

    assert_eq!(entry.real_size, 1024);

    assert_eq!(entry.flags, 0x20);

    assert!(!entry.is_directory);

    assert!(entry.resident_data.is_none());
}

#[test]
fn test_investigation_entry_detects_directory() {
    let file_name = FileNameAttribute {
        parent_record: 5,
        parent_sequence: 1,
        namespace: 1,
        allocated_size: 4096,
        real_size: 0,
        file_attributes: 0x10000000,
        name: "documentos".to_string(),
    };

    let entry = InvestigationEntry::from_file_name(43, &file_name);

    assert_eq!(entry.mft_record, 43);

    assert_eq!(entry.parent_mft_record, 5);

    assert_eq!(entry.name, "documentos");

    assert_eq!(entry.flags, 0x10000000);

    assert!(entry.is_directory);
}

#[test]
fn test_resident_data_becomes_inline_content() {
    let file_name = FileNameAttribute {
        parent_record: 5,
        parent_sequence: 1,
        namespace: 1,
        allocated_size: 10,
        real_size: 10,
        file_attributes: 0x20,
        name: "dez_bytes.txt".to_string(),
    };

    let resident_bytes = b"1234567890".to_vec();

    let data_attribute = DataAttribute {
        non_resident: false,
        real_size: 10,
        allocated_size: 10,
        resident_data: Some(resident_bytes.clone()),
        data_runs: Vec::new(),
    };

    let entry =
        InvestigationEntry::from_file_name_and_data(67, &file_name, Some(&data_attribute), 0);

    assert_eq!(entry.mft_record, 67);
    assert_eq!(entry.name, "dez_bytes.txt");
    assert_eq!(entry.real_size, 10);
    assert_eq!(entry.allocated_size, 10);

    assert_eq!(entry.resident_data, Some(resident_bytes.clone()));

    let forensic_entry = entry.to_forensic_entry(8);

    let layout = forensic_entry.content_layout;

    assert_eq!(layout.bytes_per_cluster, 4096);
    assert_eq!(layout.segments.len(), 1);

    let segment = &layout.segments[0];

    match &segment.source {
        ForensicContentSource::Inline(data) => {
            assert_eq!(data.as_slice(), resident_bytes.as_slice());
            assert_eq!(data.len(), 10);
        }

        other => panic!("expected Inline content source, got {:?}", other),
    }

    assert_eq!(segment.byte_count(layout.bytes_per_cluster), Some(10));
}

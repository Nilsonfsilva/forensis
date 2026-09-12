use forensis_core::filesystem::DataRun;
use forensis_core::filesystem::Investigation;
use forensis_core::filesystem::InvestigationEntry;

fn create_entry(
    mft_record: u64,
    parent_mft_record: u64,
    name: &str,
    allocated_size: u64,
    real_size: u64,
    flags: u32,
    is_directory: bool,
) -> InvestigationEntry {
    InvestigationEntry {
        mft_record,
        parent_mft_record,
        name: name.to_string(),
        allocated_size,
        real_size,
        flags,
        mft_flags: 0,
        is_directory,
        data_runs: Vec::<DataRun>::new(),
        resident_data: None,
    }
}

#[test]
fn test_create_empty_investigation() {
    let investigation = Investigation::new(8);

    assert_eq!(investigation.entry_count(), 0);

    assert!(investigation.entries().is_empty());
}

#[test]
fn test_add_investigation_entry() {
    let mut investigation = Investigation::new(8);

    let entry = create_entry(5, 5, "document.txt", 4096, 2048, 0x00000000, false);

    investigation.add_entry(entry);

    assert_eq!(investigation.entry_count(), 1);

    let stored = &investigation.entries()[0];

    assert_eq!(stored.mft_record, 5);

    assert_eq!(stored.parent_mft_record, 5);

    assert_eq!(stored.name, "document.txt");

    assert_eq!(stored.allocated_size, 4096);

    assert_eq!(stored.real_size, 2048);

    assert_eq!(stored.flags, 0x00000000);

    assert!(!stored.is_directory);

    assert!(stored.data_runs.is_empty());

    assert!(stored.resident_data.is_none());
}

#[test]
fn test_investigation_stores_multiple_entries() {
    let mut investigation = Investigation::new(8);

    let file = create_entry(5, 2, "document.txt", 4096, 2048, 0x00000000, false);

    let directory = create_entry(6, 5, "Documents", 0, 0, 0x10000000, true);

    investigation.add_entry(file);

    investigation.add_entry(directory);

    assert_eq!(investigation.entry_count(), 2);

    assert_eq!(investigation.entries()[0].name, "document.txt");

    assert_eq!(investigation.entries()[1].name, "Documents");

    assert!(!investigation.entries()[0].is_directory);

    assert!(investigation.entries()[1].is_directory);
}

#[test]
fn test_investigation_finds_children_of_directory() {
    let mut investigation = Investigation::new(8);

    /*
     * Directory MFT 5:
     *
     *     Documents -> MFT 6
     *     image.jpg -> MFT 7
     */
    investigation.add_entry(create_entry(6, 5, "Documents", 0, 0, 0x10000000, true));

    investigation.add_entry(create_entry(7, 5, "image.jpg", 4096, 4096, 0, false));

    let children = investigation.children_of(5);

    assert_eq!(children.len(), 2);

    assert_eq!(children[0].mft_record, 6);

    assert_eq!(children[1].mft_record, 7);
}

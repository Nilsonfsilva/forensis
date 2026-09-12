use forensis_core::filesystem::{IndexEntry, IndexRoot, Investigation, NtfsDirectory};

#[test]
fn test_add_directory_to_investigation() {
    let index_root = create_index_root();

    let directory = NtfsDirectory::from_index_root(5, &index_root)
        .expect("INDEX_ROOT should create a directory");

    let mut investigation = Investigation::new(8);

    investigation
        .add_directory(&directory)
        .expect("Directory should be added to investigation");

    /*
     * The directory itself is MFT record 5.
     *
     * The INDEX_ROOT contains two INDEX_ENTRY structures.
     *
     * entry_1 -> MFT 42
     * entry_2 -> MFT 43
     *
     * These entries belong to the directory structure and
     * must remain available through NtfsDirectory.
     *
     * They must NOT be materialized as InvestigationEntry
     * objects here, because the MFT parser already discovers
     * objects through their FILE_NAME attributes.
     *
     * Materializing both sources would cause the same logical
     * filesystem objects to appear twice in the investigation.
     */

    assert_eq!(investigation.directory_count(), 1);

    assert_eq!(investigation.entry_count(), 0);

    let directories = investigation.directories();

    assert_eq!(directories.len(), 1);

    assert_eq!(directories[0].mft_record, 5);

    assert_eq!(directories[0].entry_count(), 2);

    assert_eq!(directories[0].entries[0].file_reference, 42);

    assert_eq!(directories[0].entries[1].file_reference, 43);
}

fn create_index_root() -> IndexRoot {
    let file_name_1 = create_file_name("arquivo.txt", 0x20);

    let file_name_2 = create_file_name("documentos", 0x10000000);

    /*
     * The file_reference belongs to the object
     * represented by the INDEX_ENTRY.
     *
     * These values must remain associated with the
     * corresponding INDEX_ENTRY inside the directory.
     */

    let entry_1 = create_index_entry(42, file_name_1);

    let entry_2 = create_index_entry(43, file_name_2);

    IndexRoot {
        indexed_attribute_type: 0x30,
        collation_rule: 0,
        index_block_size: 4096,
        entries: vec![entry_1, entry_2],
    }
}

fn create_index_entry(file_reference: u64, key: Vec<u8>) -> IndexEntry {
    let entry_length = 16 + key.len();

    IndexEntry {
        file_reference,
        entry_length: entry_length as u16,
        key_length: key.len() as u16,
        flags: 0,
        key,
    }
}

fn create_file_name(name: &str, flags: u32) -> Vec<u8> {
    let utf16: Vec<u16> = name.encode_utf16().collect();

    let mut data = vec![0u8; 66 + utf16.len() * 2];

    /*
     * Parent directory reference.
     *
     * The files are children of MFT record 5.
     */
    data[0..8].copy_from_slice(&5u64.to_le_bytes());

    /*
     * Allocated size.
     */
    data[40..48].copy_from_slice(&4096u64.to_le_bytes());

    /*
     * Real size.
     */
    data[48..56].copy_from_slice(&1024u64.to_le_bytes());

    /*
     * File attributes.
     */
    data[56..60].copy_from_slice(&flags.to_le_bytes());

    /*
     * File name length in UTF-16 characters.
     */
    data[64] = utf16.len() as u8;

    /*
     * Namespace.
     *
     * 1 = Win32 namespace.
     */
    data[65] = 1;

    /*
     * UTF-16 file name.
     */
    for (index, character) in utf16.iter().enumerate() {
        let offset = 66 + index * 2;

        data[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }

    data
}

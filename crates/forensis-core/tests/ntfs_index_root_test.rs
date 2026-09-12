use forensis_core::filesystem::IndexRoot;

#[test]
fn test_parse_index_root() {
    let mut data = vec![0u8; 128];

    // ---------------------------------------------------------
    // INDEX_ROOT header
    // ---------------------------------------------------------

    // Indexed attribute type = $FILE_NAME (0x30)
    data[0..4].copy_from_slice(&0x30u32.to_le_bytes());

    // Collation rule = binary
    data[4..8].copy_from_slice(&0u32.to_le_bytes());

    // Index block size
    data[8..12].copy_from_slice(&4096u32.to_le_bytes());

    // Clusters per index block
    data[12] = 1;

    // ---------------------------------------------------------
    // INDEX_HEADER
    //
    // Offset 16
    // ---------------------------------------------------------

    // Offset to first INDEX_ENTRY
    // Relative to the beginning of INDEX_HEADER.
    data[16..20].copy_from_slice(&16u32.to_le_bytes());

    // Total size of INDEX_ENTRY area
    data[20..24].copy_from_slice(&32u32.to_le_bytes());

    // Allocated size of INDEX_ENTRY area
    data[24..28].copy_from_slice(&32u32.to_le_bytes());

    // Flags
    data[28..32].copy_from_slice(&0u32.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_ENTRY
    //
    // INDEX_HEADER starts at 16.
    //
    // First entry:
    // 16 + 16 = 32
    // ---------------------------------------------------------

    let entry = 32;

    // File reference
    data[entry..entry + 8].copy_from_slice(&5u64.to_le_bytes());

    // INDEX_ENTRY length
    data[entry + 8..entry + 10].copy_from_slice(&16u16.to_le_bytes());

    // Key length = 0
    data[entry + 10..entry + 12].copy_from_slice(&0u16.to_le_bytes());

    // Flags = normal entry
    data[entry + 12..entry + 14].copy_from_slice(&0u16.to_le_bytes());

    // Reserved
    data[entry + 14..entry + 16].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // Final INDEX_ENTRY
    //
    // The final entry is marked with flag 0x0002.
    // ---------------------------------------------------------

    let final_entry = entry + 16;

    // File reference
    data[final_entry..final_entry + 8].copy_from_slice(&0u64.to_le_bytes());

    // Final entry length
    data[final_entry + 8..final_entry + 10].copy_from_slice(&16u16.to_le_bytes());

    // Key length = 0
    data[final_entry + 10..final_entry + 12].copy_from_slice(&0u16.to_le_bytes());

    // Flags = LAST_ENTRY
    data[final_entry + 12..final_entry + 14].copy_from_slice(&0x0002u16.to_le_bytes());

    // Reserved
    data[final_entry + 14..final_entry + 16].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // Parse
    // ---------------------------------------------------------

    let parsed = IndexRoot::parse(&data).expect("INDEX_ROOT should be valid");

    // ---------------------------------------------------------
    // Validate
    // ---------------------------------------------------------

    assert_eq!(parsed.indexed_attribute_type, 0x30);

    assert_eq!(parsed.collation_rule, 0);

    assert_eq!(parsed.index_block_size, 4096);

    assert_eq!(parsed.entries.len(), 1);

    assert_eq!(parsed.entries[0].file_reference, 5);

    assert_eq!(parsed.entries[0].entry_length, 16);

    assert_eq!(parsed.entries[0].key_length, 0);
}

#[test]
fn test_rejects_short_index_root() {
    let data = vec![0u8; 10];

    let result = IndexRoot::parse(&data);

    assert!(result.is_err(), "Short INDEX_ROOT should be rejected");
}

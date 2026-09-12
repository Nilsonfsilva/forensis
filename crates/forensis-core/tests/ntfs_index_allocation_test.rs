use forensis_core::filesystem::IndexAllocation;

#[test]
fn test_parse_index_allocation() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"INDX");

    // ---------------------------------------------------------
    // Update Sequence Array
    // ---------------------------------------------------------

    data[4..6].copy_from_slice(&40u16.to_le_bytes());

    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    // Update Sequence Number
    data[40..42].copy_from_slice(&0xAAAAu16.to_le_bytes());

    // Replacement sector 1
    data[42..44].copy_from_slice(&0x1111u16.to_le_bytes());

    // Replacement sector 2
    data[44..46].copy_from_slice(&0x2222u16.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_HEADER
    // ---------------------------------------------------------

    data[24..28].copy_from_slice(&16u32.to_le_bytes());

    data[28..32].copy_from_slice(&16u32.to_le_bytes());

    data[32..36].copy_from_slice(&16u32.to_le_bytes());

    data[36..40].copy_from_slice(&0u32.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_ENTRY
    //
    // INDEX_HEADER starts at 24.
    //
    // Entry offset = 16
    // Absolute offset = 24 + 16 = 40
    //
    // However, offset 40 is occupied by USA.
    //
    // Therefore the entry offset must account for the USA.
    // ---------------------------------------------------------

    data[24..28].copy_from_slice(&24u32.to_le_bytes());

    let entry = 48;

    data[entry..entry + 8].copy_from_slice(&5u64.to_le_bytes());

    data[entry + 8..entry + 10].copy_from_slice(&16u16.to_le_bytes());

    data[entry + 10..entry + 12].copy_from_slice(&0u16.to_le_bytes());

    data[entry + 12..entry + 14].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // Sector trailers
    // ---------------------------------------------------------

    data[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());

    data[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

    let allocation = IndexAllocation::parse(&data).expect("INDEX_ALLOCATION should be valid");

    assert_eq!(allocation.entries().len(), 1);

    assert_eq!(allocation.entries()[0].file_reference, 5);

    assert_eq!(&allocation.raw()[510..512], &0x1111u16.to_le_bytes());

    assert_eq!(&allocation.raw()[1022..1024], &0x2222u16.to_le_bytes());
}

#[test]
fn test_parse_multiple_index_entries() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"INDX");

    // ---------------------------------------------------------
    // Update Sequence Array
    // ---------------------------------------------------------

    data[4..6].copy_from_slice(&40u16.to_le_bytes());

    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[40..42].copy_from_slice(&0xAAAAu16.to_le_bytes());

    data[42..44].copy_from_slice(&0x1111u16.to_le_bytes());

    data[44..46].copy_from_slice(&0x2222u16.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_HEADER
    // ---------------------------------------------------------

    /*
     * INDEX_HEADER = 24
     *
     * Entry offset relative to INDEX_HEADER = 24
     *
     * Absolute:
     *
     * 24 + 24 = 48
     */

    data[24..28].copy_from_slice(&24u32.to_le_bytes());

    // Two entries of 16 bytes each.
    data[28..32].copy_from_slice(&32u32.to_le_bytes());

    data[32..36].copy_from_slice(&32u32.to_le_bytes());

    data[36..40].copy_from_slice(&0u32.to_le_bytes());

    // ---------------------------------------------------------
    // First INDEX_ENTRY
    // ---------------------------------------------------------

    let first = 48;

    data[first..first + 8].copy_from_slice(&5u64.to_le_bytes());

    data[first + 8..first + 10].copy_from_slice(&16u16.to_le_bytes());

    data[first + 10..first + 12].copy_from_slice(&0u16.to_le_bytes());

    data[first + 12..first + 14].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // Second INDEX_ENTRY
    // ---------------------------------------------------------

    let second = first + 16;

    data[second..second + 8].copy_from_slice(&10u64.to_le_bytes());

    data[second + 8..second + 10].copy_from_slice(&16u16.to_le_bytes());

    data[second + 10..second + 12].copy_from_slice(&0u16.to_le_bytes());

    data[second + 12..second + 14].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // Sector trailers
    // ---------------------------------------------------------

    data[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());

    data[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

    // ---------------------------------------------------------
    // Parse
    // ---------------------------------------------------------

    let allocation = IndexAllocation::parse(&data).expect("INDEX_ALLOCATION should be valid");

    // ---------------------------------------------------------
    // Validate
    // ---------------------------------------------------------

    assert_eq!(allocation.entries().len(), 2);

    assert_eq!(allocation.entries()[0].file_reference, 5);

    assert_eq!(allocation.entries()[1].file_reference, 10);
}

#[test]
fn test_parse_index_allocation_with_update_sequence_fixup() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"INDX");

    // USA offset
    data[4..6].copy_from_slice(&40u16.to_le_bytes());

    // USA count = 3
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    // Update Sequence Number
    data[40..42].copy_from_slice(&0xAAAAu16.to_le_bytes());

    // Replacement sector 1
    data[42..44].copy_from_slice(&0x1111u16.to_le_bytes());

    // Replacement sector 2
    data[44..46].copy_from_slice(&0x2222u16.to_le_bytes());

    // INDEX_HEADER
    data[24..28].copy_from_slice(&32u32.to_le_bytes());

    data[28..32].copy_from_slice(&16u32.to_le_bytes());

    let entry = 56;

    data[entry..entry + 8].copy_from_slice(&42u64.to_le_bytes());

    data[entry + 8..entry + 10].copy_from_slice(&16u16.to_le_bytes());

    data[entry + 10..entry + 12].copy_from_slice(&0u16.to_le_bytes());

    data[entry + 12..entry + 14].copy_from_slice(&0x0002u16.to_le_bytes());

    // Sector trailers
    data[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());

    data[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

    let allocation =
        IndexAllocation::parse(&data).expect("INDEX_ALLOCATION with USA should be valid");

    assert_eq!(&allocation.raw()[510..512], &0x1111u16.to_le_bytes());

    assert_eq!(&allocation.raw()[1022..1024], &0x2222u16.to_le_bytes());

    assert!(allocation.entries().is_empty());
}

#[test]
fn test_rejects_invalid_update_sequence_number() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"INDX");

    data[4..6].copy_from_slice(&40u16.to_le_bytes());

    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[40..42].copy_from_slice(&0xAAAAu16.to_le_bytes());

    data[42..44].copy_from_slice(&0x1111u16.to_le_bytes());

    data[44..46].copy_from_slice(&0x2222u16.to_le_bytes());

    data[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());

    data[1022..1024].copy_from_slice(&0xBBBBu16.to_le_bytes());

    let result = IndexAllocation::parse(&data);

    assert!(result.is_err(), "Invalid USA sequence should be rejected");
}

#[test]
fn test_rejects_invalid_signature() {
    let data = vec![0u8; 96];

    let result = IndexAllocation::parse(&data);

    assert!(result.is_err(), "Invalid INDX signature should be rejected");
}

#[test]
fn test_rejects_short_index_allocation() {
    let data = vec![0u8; 20];

    let result = IndexAllocation::parse(&data);

    assert!(result.is_err(), "Short INDEX_ALLOCATION should be rejected");
}

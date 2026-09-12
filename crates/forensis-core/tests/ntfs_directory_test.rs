use forensis_core::filesystem::{IndexAllocation, IndexRoot, NtfsDirectory};

#[test]
fn test_create_directory_from_index_root() {
    let mut data = vec![0u8; 64];

    // ---------------------------------------------------------
    // INDEX_ROOT HEADER
    // ---------------------------------------------------------

    // Indexed attribute type = $FILE_NAME
    data[0..4].copy_from_slice(&0x30u32.to_le_bytes());

    // Collation rule = binary
    data[4..8].copy_from_slice(&0u32.to_le_bytes());

    // Index block size
    data[8..12].copy_from_slice(&4096u32.to_le_bytes());

    // Clusters per index block
    data[12..16].copy_from_slice(&1u32.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_HEADER
    //
    // Starts at offset 16.
    // ---------------------------------------------------------

    // Offset to first INDEX_ENTRY.
    //
    // Relative to INDEX_HEADER.
    //
    // 16 + 16 = 32
    data[16..20].copy_from_slice(&16u32.to_le_bytes());

    // Total size of INDEX_HEADER + entries
    data[20..24].copy_from_slice(&32u32.to_le_bytes());

    // Allocated size
    data[24..28].copy_from_slice(&32u32.to_le_bytes());

    // Flags
    data[28..32].copy_from_slice(&0u32.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_ENTRY
    // ---------------------------------------------------------

    let entry = 32;

    // MFT file reference
    data[entry..entry + 8].copy_from_slice(&5u64.to_le_bytes());

    // INDEX_ENTRY length
    data[entry + 8..entry + 10].copy_from_slice(&16u16.to_le_bytes());

    // Key length
    data[entry + 10..entry + 12].copy_from_slice(&0u16.to_le_bytes());

    // Flags
    data[entry + 12..entry + 14].copy_from_slice(&0u16.to_le_bytes());

    // Reserved
    data[entry + 14..entry + 16].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // LAST INDEX_ENTRY
    // ---------------------------------------------------------

    let end_entry = entry + 16;

    // MFT file reference
    data[end_entry..end_entry + 8].copy_from_slice(&0u64.to_le_bytes());

    // INDEX_ENTRY length
    data[end_entry + 8..end_entry + 10].copy_from_slice(&16u16.to_le_bytes());

    // Key length
    data[end_entry + 10..end_entry + 12].copy_from_slice(&0u16.to_le_bytes());

    // Flags = LAST_ENTRY
    data[end_entry + 12..end_entry + 14].copy_from_slice(&0x0002u16.to_le_bytes());

    // Reserved
    data[end_entry + 14..end_entry + 16].copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // PARSE INDEX_ROOT
    // ---------------------------------------------------------

    let root = IndexRoot::parse(&data).expect("INDEX_ROOT should be valid");

    // ---------------------------------------------------------
    // CREATE DIRECTORY
    // ---------------------------------------------------------

    let mut directory =
        NtfsDirectory::from_index_root(5, &root).expect("Directory should be created");

    // ---------------------------------------------------------
    // VALIDATE INDEX_ROOT
    // ---------------------------------------------------------

    assert_eq!(directory.mft_record, 5);

    assert_eq!(directory.entry_count(), 1);

    assert_eq!(directory.entries[0].file_reference, 5);

    // ---------------------------------------------------------
    // INDEX_ALLOCATION
    //
    // Simulates another index block containing
    // an additional directory entry.
    // ---------------------------------------------------------

    let mut allocation_data = vec![0u8; 1024];

    // ---------------------------------------------------------
    // INDX signature
    // ---------------------------------------------------------

    allocation_data[0..4].copy_from_slice(b"INDX");

    // ---------------------------------------------------------
    // INDEX_ALLOCATION header
    //
    // USA:
    //
    // offset = 40
    // count  = 3
    // ---------------------------------------------------------

    allocation_data[4..6].copy_from_slice(&40u16.to_le_bytes());

    allocation_data[6..8].copy_from_slice(&3u16.to_le_bytes());

    // Update Sequence Number
    allocation_data[40..42].copy_from_slice(&0xAAAAu16.to_le_bytes());

    // Replacement values
    allocation_data[42..44].copy_from_slice(&0x1111u16.to_le_bytes());

    allocation_data[44..46].copy_from_slice(&0x2222u16.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_HEADER
    // ---------------------------------------------------------

    // Entry offset relative to INDEX_HEADER.
    //
    // INDEX_HEADER = 24
    // Entry absolute offset = 48
    //
    // 24 + 24 = 48
    allocation_data[24..28].copy_from_slice(&24u32.to_le_bytes());

    // Total size of entries
    //
    // One normal entry + one LAST_ENTRY.
    allocation_data[28..32].copy_from_slice(&32u32.to_le_bytes());

    allocation_data[32..36].copy_from_slice(&32u32.to_le_bytes());

    allocation_data[36..40].copy_from_slice(&0u32.to_le_bytes());

    // ---------------------------------------------------------
    // INDEX_ENTRY
    // ---------------------------------------------------------

    let allocation_entry = 48;

    // MFT reference = 10
    allocation_data[allocation_entry..allocation_entry + 8].copy_from_slice(&10u64.to_le_bytes());

    // Entry length
    allocation_data[allocation_entry + 8..allocation_entry + 10]
        .copy_from_slice(&16u16.to_le_bytes());

    // Key length
    allocation_data[allocation_entry + 10..allocation_entry + 12]
        .copy_from_slice(&0u16.to_le_bytes());

    // Flags
    allocation_data[allocation_entry + 12..allocation_entry + 14]
        .copy_from_slice(&0u16.to_le_bytes());

    // ---------------------------------------------------------
    // LAST INDEX_ENTRY
    // ---------------------------------------------------------

    let last = allocation_entry + 16;

    allocation_data[last..last + 8].copy_from_slice(&0u64.to_le_bytes());

    allocation_data[last + 8..last + 10].copy_from_slice(&16u16.to_le_bytes());

    allocation_data[last + 10..last + 12].copy_from_slice(&0u16.to_le_bytes());

    allocation_data[last + 12..last + 14].copy_from_slice(&0x0002u16.to_le_bytes());

    // ---------------------------------------------------------
    // Sector trailers for USA fixup
    // ---------------------------------------------------------

    allocation_data[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());

    allocation_data[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

    // ---------------------------------------------------------
    // PARSE INDEX_ALLOCATION
    // ---------------------------------------------------------

    let allocation =
        IndexAllocation::parse(&allocation_data).expect("INDEX_ALLOCATION should be valid");

    assert_eq!(allocation.entries().len(), 1);

    assert_eq!(allocation.entries()[0].file_reference, 10);

    // ---------------------------------------------------------
    // ADD INDEX_ALLOCATION TO DIRECTORY
    // ---------------------------------------------------------

    directory
        .add_index_allocation(&allocation)
        .expect("INDEX_ALLOCATION should be added");

    // ---------------------------------------------------------
    // VALIDATE COMPLETE DIRECTORY
    // ---------------------------------------------------------

    assert_eq!(directory.entry_count(), 2);

    assert_eq!(directory.entries[0].file_reference, 5);

    assert_eq!(directory.entries[1].file_reference, 10);
}

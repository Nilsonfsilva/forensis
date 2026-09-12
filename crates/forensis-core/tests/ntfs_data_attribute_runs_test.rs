use forensis_core::filesystem::ntfs::DataAttribute;

#[test]
fn test_parse_non_resident_data_runs() {
    /*
     * Non-resident $DATA attribute.
     *
     * Runlist:
     *
     * 8 clusters at LCN 100
     * 4 clusters at LCN 250
     */

    let mut data = vec![0u8; 80];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&80u32.to_le_bytes());

    // Non-resident
    data[8] = 1;

    // Data runlist offset
    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    // Allocated size
    data[40..48].copy_from_slice(&49152u64.to_le_bytes());

    // Real size
    data[48..56].copy_from_slice(&32768u64.to_le_bytes());

    // Run 1: 8 clusters, LCN 100
    data[64] = 0x11;
    data[65] = 0x08;
    data[66] = 0x64;

    // Run 2: 4 clusters, delta +150 => LCN 250
    data[67] = 0x21;
    data[68] = 0x04;
    data[69] = 0x96;
    data[70] = 0x00;

    // Terminator
    data[71] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(attribute.non_resident);
    assert_eq!(attribute.real_size, 32768);
    assert_eq!(attribute.allocated_size, 49152);
    assert!(attribute.resident_data.is_none());

    assert_eq!(attribute.data_runs.len(), 2);

    assert_eq!(attribute.data_runs[0].lcn, Some(100));
    assert_eq!(attribute.data_runs[0].cluster_count, 8);

    assert_eq!(attribute.data_runs[1].lcn, Some(250));
    assert_eq!(attribute.data_runs[1].cluster_count, 4);
}

#[test]
fn test_parse_non_resident_sparse_run() {
    /*
     * Non-resident attribute containing a physical run
     * followed by a sparse run.
     *
     * Run 1:
     *   4 clusters at LCN 100
     *
     * Run 2:
     *   3 clusters sparse
     */

    let mut data = vec![0u8; 72];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&72u32.to_le_bytes());
    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&28672u64.to_le_bytes());
    data[48..56].copy_from_slice(&28672u64.to_le_bytes());

    // Physical run: 4 clusters at LCN 100
    data[64] = 0x11;
    data[65] = 0x04;
    data[66] = 0x64;

    // Sparse run: 3 clusters
    data[67] = 0x01;
    data[68] = 0x03;

    // Terminator
    data[69] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(attribute.non_resident);
    assert_eq!(attribute.data_runs.len(), 2);

    assert_eq!(attribute.data_runs[0].lcn, Some(100));
    assert_eq!(attribute.data_runs[0].cluster_count, 4);

    assert_eq!(attribute.data_runs[1].lcn, None);
    assert_eq!(attribute.data_runs[1].cluster_count, 3);
}

#[test]
fn test_rejects_invalid_attribute_type() {
    let mut data = vec![0u8; 64];

    // Not $DATA
    data[0..4].copy_from_slice(&0x30u32.to_le_bytes());

    data[4..8].copy_from_slice(&64u32.to_le_bytes());

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_attribute_length_larger_than_buffer() {
    let mut data = vec![0u8; 64];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    // Attribute claims 80 bytes, but buffer has only 64.
    data[4..8].copy_from_slice(&80u32.to_le_bytes());

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_attribute_length_smaller_than_common_header() {
    let mut data = vec![0u8; 16];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    // Smaller than the minimum required common header.
    data[4..8].copy_from_slice(&8u32.to_le_bytes());

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_resident_attribute_too_short() {
    let mut data = vec![0u8; 22];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&22u32.to_le_bytes());

    // Resident
    data[8] = 0;

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_resident_value_outside_attribute() {
    let mut data = vec![0u8; 29];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&29u32.to_le_bytes());

    // Resident
    data[8] = 0;

    // Value length = 10
    data[16..20].copy_from_slice(&10u32.to_le_bytes());

    // Value offset = 24
    data[20..22].copy_from_slice(&24u16.to_le_bytes());

    // 24 + 10 = 34 > 29
    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_resident_value_offset_before_resident_header() {
    let mut data = vec![0u8; 29];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&29u32.to_le_bytes());

    // Resident
    data[8] = 0;

    // Value length = 5
    data[16..20].copy_from_slice(&5u32.to_le_bytes());

    // Invalid offset: inside the resident header.
    data[20..22].copy_from_slice(&20u16.to_le_bytes());

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_resident_zero_length_data() {
    let mut data = vec![0u8; 24];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&24u32.to_le_bytes());

    // Resident
    data[8] = 0;

    // Value length = 0
    data[16..20].copy_from_slice(&0u32.to_le_bytes());

    // Value offset = 24
    data[20..22].copy_from_slice(&24u16.to_le_bytes());

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(!attribute.non_resident);
    assert_eq!(attribute.real_size, 0);
    assert_eq!(attribute.allocated_size, 0);

    assert_eq!(attribute.resident_data.as_ref().unwrap(), &Vec::<u8>::new());

    assert!(attribute.data_runs.is_empty());
}

#[test]
fn test_rejects_non_resident_attribute_too_short() {
    let mut data = vec![0u8; 63];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&63u32.to_le_bytes());

    // Non-resident
    data[8] = 1;

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_runlist_offset_outside_attribute() {
    let mut data = vec![0u8; 64];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&64u32.to_le_bytes());

    // Non-resident
    data[8] = 1;

    // Runlist offset == attribute length.
    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_non_resident_runlist_without_terminator() {
    let mut data = vec![0u8; 67];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&67u32.to_le_bytes());

    // Non-resident
    data[8] = 1;

    // Runlist offset
    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    // Valid run, but no 0x00 terminator.
    data[64] = 0x11;
    data[65] = 0x01;
    data[66] = 0x64;

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_invalid_non_resident_runlist() {
    let mut data = vec![0u8; 68];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&68u32.to_le_bytes());

    // Non-resident
    data[8] = 1;

    // Runlist offset
    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    // Invalid DataRun: cluster count = zero.
    data[64] = 0x11;
    data[65] = 0x00;
    data[66] = 0x64;

    // Terminator
    data[67] = 0x00;

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_non_resident_zero_real_size() {
    let mut data = vec![0u8; 65];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[4..8].copy_from_slice(&65u32.to_le_bytes());

    // Non-resident
    data[8] = 1;

    // Runlist offset
    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    // Allocated size = 0
    data[40..48].copy_from_slice(&0u64.to_le_bytes());

    // Real size = 0
    data[48..56].copy_from_slice(&0u64.to_le_bytes());

    // Empty runlist
    data[64] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(attribute.non_resident);
    assert_eq!(attribute.real_size, 0);
    assert_eq!(attribute.allocated_size, 0);
    assert!(attribute.data_runs.is_empty());
}

use forensis_core::filesystem::ntfs::DataAttribute;

#[test]
fn test_parse_resident_data_larger_content() {
    /*
     * Resident $DATA containing 32 bytes.
     *
     * The goal is to verify that the parser does not depend
     * on small contents like "hello".
     */

    let content = b"0123456789ABCDEF0123456789ABCDEF";

    let value_offset = 24usize;

    let attribute_length = value_offset + content.len();

    let mut data = vec![0u8; attribute_length];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());

    data[8] = 0;

    data[14..16].copy_from_slice(&1u16.to_le_bytes());

    data[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());

    data[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes());

    data[value_offset..].copy_from_slice(content);

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(!attribute.non_resident);

    assert_eq!(attribute.real_size, content.len() as u64);

    assert_eq!(attribute.allocated_size, content.len() as u64);

    assert_eq!(attribute.resident_data, Some(content.to_vec()));

    assert!(attribute.data_runs.is_empty());
}

#[test]
fn test_parse_resident_data_at_exact_attribute_end() {
    /*
     * The resident content ends exactly at the last
     * byte of the attribute.
     */

    let content = b"NTFS";

    let value_offset = 24usize;

    let attribute_length = value_offset + content.len();

    let mut data = vec![0u8; attribute_length];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());

    data[8] = 0;

    data[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());

    data[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes());

    data[value_offset..].copy_from_slice(content);

    let attribute = DataAttribute::parse(&data).unwrap();

    assert_eq!(attribute.resident_data, Some(content.to_vec()));

    assert_eq!(attribute.real_size, 4);

    assert_eq!(attribute.allocated_size, 4);
}

#[test]
fn test_parse_non_resident_multiple_runs() {
    /*
     * Runlist:
     *
     * 2 clusters at LCN 100
     * 3 clusters at LCN 150
     * 1 cluster at LCN 200
     */

    let mut data = vec![0u8; 80];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&80u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&24576u64.to_le_bytes());

    data[48..56].copy_from_slice(&24576u64.to_le_bytes());

    /*
     * Run 1:
     * 2 clusters
     * LCN delta +100
     */
    data[64] = 0x11;
    data[65] = 0x02;
    data[66] = 0x64;

    /*
     * Run 2:
     * 3 clusters
     * LCN delta +50
     */
    data[67] = 0x11;
    data[68] = 0x03;
    data[69] = 0x32;

    /*
     * Run 3:
     * 1 cluster
     * LCN delta +50
     */
    data[70] = 0x11;
    data[71] = 0x01;
    data[72] = 0x32;

    data[73] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(attribute.non_resident);

    assert_eq!(attribute.data_runs.len(), 3);

    assert_eq!(attribute.data_runs[0].lcn, Some(100));
    assert_eq!(attribute.data_runs[0].cluster_count, 2);

    assert_eq!(attribute.data_runs[1].lcn, Some(150));
    assert_eq!(attribute.data_runs[1].cluster_count, 3);

    assert_eq!(attribute.data_runs[2].lcn, Some(200));
    assert_eq!(attribute.data_runs[2].cluster_count, 1);
}

#[test]
fn test_parse_non_resident_sparse_run_between_physical_runs() {
    /*
     * Runlist:
     *
     * 2 clusters at LCN 100
     * 3 clusters sparse
     * 2 clusters at LCN 150
     */

    let mut data = vec![0u8; 80];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&80u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&28672u64.to_le_bytes());

    data[48..56].copy_from_slice(&28672u64.to_le_bytes());

    /*
     * Physical run:
     * 2 clusters at LCN 100
     */
    data[64] = 0x11;
    data[65] = 0x02;
    data[66] = 0x64;

    /*
     * Sparse run:
     * 3 clusters
     */
    data[67] = 0x01;
    data[68] = 0x03;

    /*
     * Physical run:
     * 2 clusters
     * delta +50
     *
     * Sparse run does not alter the previous LCN.
     */
    data[69] = 0x11;
    data[70] = 0x02;
    data[71] = 0x32;

    data[72] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert_eq!(attribute.data_runs.len(), 3);

    assert_eq!(attribute.data_runs[0].lcn, Some(100));
    assert_eq!(attribute.data_runs[0].cluster_count, 2);

    assert_eq!(attribute.data_runs[1].lcn, None);
    assert_eq!(attribute.data_runs[1].cluster_count, 3);

    assert_eq!(attribute.data_runs[2].lcn, Some(150));
    assert_eq!(attribute.data_runs[2].cluster_count, 2);
}

#[test]
fn test_parse_non_resident_empty_runlist() {
    /*
     * A non-resident attribute may have a runlist
     * that starts immediately with the terminator.
     *
     * In this case there are no physical runs.
     */

    let mut data = vec![0u8; 65];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&65u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&0u64.to_le_bytes());

    data[48..56].copy_from_slice(&0u64.to_le_bytes());

    data[64] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(attribute.non_resident);

    assert!(attribute.data_runs.is_empty());

    assert_eq!(attribute.real_size, 0);

    assert_eq!(attribute.allocated_size, 0);

    assert!(attribute.resident_data.is_none());
}

#[test]
fn test_parse_non_resident_bytes_after_terminator_are_ignored() {
    /*
     * The runlist ends at 0x00.
     *
     * Bytes after the terminator belong to the rest
     * of the attribute and must not be interpreted as runs.
     */

    let mut data = vec![0u8; 76];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&76u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&4096u64.to_le_bytes());

    data[48..56].copy_from_slice(&4096u64.to_le_bytes());

    /*
     * Run:
     * 1 cluster at LCN 100
     */
    data[64] = 0x11;
    data[65] = 0x01;
    data[66] = 0x64;

    /*
     * Terminator
     */
    data[67] = 0x00;

    /*
     * Bytes after the terminator.
     */
    data[68] = 0xFF;
    data[69] = 0xFF;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert_eq!(attribute.data_runs.len(), 1);

    assert_eq!(attribute.data_runs[0].lcn, Some(100));

    assert_eq!(attribute.data_runs[0].cluster_count, 1);
}

#[test]
fn test_rejects_non_resident_truncated_run() {
    /*
     * The attribute has a runlist that starts with:
     *
     * 0x21
     *
     * 1 byte for cluster count
     * 2 bytes for LCN
     *
     * But only one byte of the LCN is present.
     */

    let mut data = vec![0u8; 67];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&67u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&4096u64.to_le_bytes());

    data[48..56].copy_from_slice(&4096u64.to_le_bytes());

    data[64] = 0x21;
    data[65] = 0x01;
    data[66] = 0x64;

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_non_resident_runlist_without_terminator() {
    /*
     * Valid run, but without the 0x00 terminator.
     */

    let mut data = vec![0u8; 67];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&67u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&4096u64.to_le_bytes());

    data[48..56].copy_from_slice(&4096u64.to_le_bytes());

    data[64] = 0x11;
    data[65] = 0x01;
    data[66] = 0x64;

    let result = DataAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_non_resident_zero_real_size() {
    /*
     * Non-resident attribute with real_size = 0.
     *
     * This is valid for an empty file, as long as
     * the attribute structure and its runlist are valid.
     */

    let mut data = vec![0u8; 65];

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    data[4..8].copy_from_slice(&65u32.to_le_bytes());

    data[8] = 1;

    data[32..34].copy_from_slice(&64u16.to_le_bytes());

    data[40..48].copy_from_slice(&0u64.to_le_bytes());

    data[48..56].copy_from_slice(&0u64.to_le_bytes());

    data[64] = 0x00;

    let attribute = DataAttribute::parse(&data).unwrap();

    assert!(attribute.non_resident);

    assert_eq!(attribute.real_size, 0);

    assert_eq!(attribute.allocated_size, 0);

    assert!(attribute.data_runs.is_empty());
}

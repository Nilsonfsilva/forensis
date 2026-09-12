use forensis_core::filesystem::ntfs::DataRun;

#[test]
fn test_parse_single_data_run() {
    let data = [0x11, 0x08, 0x64, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].lcn, Some(100));
    assert_eq!(runs[0].cluster_count, 8);
}

#[test]
fn test_parse_multiple_data_runs() {
    let data = [0x11, 0x08, 0x64, 0x21, 0x04, 0x96, 0x00, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].lcn, Some(100));
    assert_eq!(runs[0].cluster_count, 8);
    assert_eq!(runs[1].lcn, Some(250));
    assert_eq!(runs[1].cluster_count, 4);
}

#[test]
fn test_parse_negative_relative_lcn() {
    let data = [0x11, 0x01, 0x64, 0x11, 0x01, 0xEC, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].lcn, Some(100));
    assert_eq!(runs[1].lcn, Some(80));
}

#[test]
fn test_parse_sparse_data_run() {
    let data = [0x01, 0x04, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].lcn, None);
    assert_eq!(runs[0].cluster_count, 4);
}

#[test]
fn test_parse_large_cluster_count() {
    let data = [0x12, 0x34, 0x12, 0x64, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].lcn, Some(100));
    assert_eq!(runs[0].cluster_count, 4660);
}

#[test]
fn test_parse_large_lcn_delta() {
    let data = [0x21, 0x01, 0x34, 0x12, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].lcn, Some(4660));
    assert_eq!(runs[0].cluster_count, 1);
}

#[test]
fn test_parse_negative_relative_lcn_two_bytes() {
    /*
     * First run:
     *
     * LCN 1000
     *
     * 1000 = 0x03E8
     *
     * Little-endian:
     *
     * E8 03
     *
     * Second run:
     *
     * delta = -200
     *
     * -200 = 0xFF38 as signed 16-bit
     *
     * Little-endian:
     *
     * 38 FF
     *
     * Therefore:
     *
     * 1000 + (-200) = 800
     */
    let data = [0x21, 0x01, 0xE8, 0x03, 0x21, 0x01, 0x38, 0xFF, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].lcn, Some(1000));
    assert_eq!(runs[0].cluster_count, 1);
    assert_eq!(runs[1].lcn, Some(800));
    assert_eq!(runs[1].cluster_count, 1);
}

#[test]
fn test_rejects_truncated_data_run() {
    let data = [0x21, 0x01, 0x64];

    let result = DataRun::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_zero_cluster_count() {
    let data = [0x11, 0x00, 0x64, 0x00];

    let result = DataRun::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_zero_cluster_count_size() {
    let data = [0x10, 0x64, 0x00];

    let result = DataRun::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_negative_resulting_lcn() {
    let data = [0x11, 0x01, 0x0A, 0x11, 0x01, 0xEC, 0x00];

    let result = DataRun::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_lcn_overflow() {
    let data = [
        0x81, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x11, 0x01, 0x01, 0x00,
    ];

    let result = DataRun::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_empty_runlist() {
    let data = [0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert!(runs.is_empty());
}

#[test]
fn test_rejects_runlist_without_terminator() {
    let data = [0x11, 0x08, 0x64];

    let result = DataRun::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_sparse_run_between_physical_runs() {
    /*
     * First run:
     *
     * 4 clusters at LCN 100.
     *
     * Second run:
     *
     * 3 sparse clusters.
     *
     * Third run:
     *
     * delta = +20.
     *
     * Sparse runs must not modify previous_lcn.
     *
     * Therefore:
     *
     * 100 + 20 = 120.
     */
    let data = [0x11, 0x04, 0x64, 0x01, 0x03, 0x11, 0x01, 0x14, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 3);

    assert_eq!(runs[0].lcn, Some(100));
    assert_eq!(runs[0].cluster_count, 4);

    assert_eq!(runs[1].lcn, None);
    assert_eq!(runs[1].cluster_count, 3);

    assert_eq!(runs[2].lcn, Some(120));
    assert_eq!(runs[2].cluster_count, 1);
}

#[test]
fn test_parse_sparse_run_followed_by_negative_relative_lcn() {
    /*
     * First run:
     *
     * LCN 100.
     *
     * Second run:
     *
     * 2 sparse clusters.
     *
     * Third run:
     *
     * delta = -20.
     *
     * Sparse run must not modify previous_lcn.
     */
    let data = [0x11, 0x01, 0x64, 0x01, 0x02, 0x11, 0x01, 0xEC, 0x00];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 3);

    assert_eq!(runs[0].lcn, Some(100));
    assert_eq!(runs[1].lcn, None);
    assert_eq!(runs[1].cluster_count, 2);
    assert_eq!(runs[2].lcn, Some(80));
}

#[test]
fn test_parse_negative_relative_lcn_three_bytes() {
    /*
     * First run:
     *
     * LCN 100000.
     *
     * 100000 = 0x0186A0
     *
     * Little-endian:
     *
     * A0 86 01
     *
     * Second run:
     *
     * delta = -20000.
     *
     * -20000 = 0xFFB1E0 as signed 24-bit.
     *
     * Little-endian:
     *
     * E0 B1 FF
     *
     * Therefore:
     *
     * 100000 + (-20000) = 80000.
     */
    let data = [
        0x31, 0x01, 0xA0, 0x86, 0x01, 0x31, 0x01, 0xE0, 0xB1, 0xFF, 0x00,
    ];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 2);

    assert_eq!(runs[0].lcn, Some(100000));
    assert_eq!(runs[0].cluster_count, 1);

    assert_eq!(runs[1].lcn, Some(80000));
    assert_eq!(runs[1].cluster_count, 1);
}

#[test]
fn test_parse_eight_byte_lcn_delta() {
    /*
     * LCN delta:
     *
     * 0x0000000100000000
     *
     * = 4294967296.
     */
    let data = [
        0x81, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 1);

    assert_eq!(runs[0].lcn, Some(4294967296));
    assert_eq!(runs[0].cluster_count, 1);
}

#[test]
fn test_parse_eight_byte_negative_lcn_delta() {
    /*
     * First run:
     *
     * LCN 4294967296.
     *
     * Second run:
     *
     * delta = -1.
     *
     * Therefore:
     *
     * 4294967296 - 1 = 4294967295.
     */
    let data = [
        0x81, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x81, 0x01, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
    ];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 2);

    assert_eq!(runs[0].lcn, Some(4294967296));
    assert_eq!(runs[1].lcn, Some(4294967295));
}

#[test]
fn test_parse_large_cluster_count_eight_bytes() {
    /*
     * Cluster count uses 8 bytes.
     *
     * Value:
     *
     * 0x0000000100000000
     *
     * = 4294967296 clusters.
     *
     * LCN delta = +1.
     *
     * Header = 0x18
     *
     * High nibble = 1 byte for LCN
     * Low nibble  = 8 bytes for cluster count
     */
    let data = [
        0x18, // Cluster count = 4294967296
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // LCN delta = +1
        0x01, // End of runlist
        0x00,
    ];

    let runs = DataRun::parse(&data).unwrap();

    assert_eq!(runs.len(), 1);

    assert_eq!(runs[0].lcn, Some(1));

    assert_eq!(runs[0].cluster_count, 4294967296);
}

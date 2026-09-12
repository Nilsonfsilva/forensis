use forensis_core::filesystem::ext4::Ext4Extent;

fn build_extent(
    logical_block: u32,
    length: u16,
    physical_high: u16,
    physical_low: u32,
) -> [u8; 12] {
    let mut data = [0u8; 12];

    data[0..4].copy_from_slice(&logical_block.to_le_bytes());
    data[4..6].copy_from_slice(&length.to_le_bytes());
    data[6..8].copy_from_slice(&physical_high.to_le_bytes());
    data[8..12].copy_from_slice(&physical_low.to_le_bytes());

    data
}

#[test]
fn parses_initialized_extent() {
    let data = build_extent(100, 5, 0x0001, 0x0000_2000);

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.logical_block(), 100);
    assert_eq!(extent.physical_block(), 0x0001_0000_2000);
    assert_eq!(extent.length(), 5);
    assert!(extent.is_initialized());
}

#[test]
fn parses_unwritten_extent() {
    let data = build_extent(200, 0x8005, 0, 5000);

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.logical_block(), 200);
    assert_eq!(extent.physical_block(), 5000);
    assert_eq!(extent.length(), 5);
    assert!(!extent.is_initialized());
}

#[test]
fn rejects_insufficient_data() {
    let data = [0u8; 11];

    let result = Ext4Extent::parse(&data);

    assert!(result.is_err());
}

#[test]
fn accepts_exact_extent_size() {
    let data = [0u8; Ext4Extent::SIZE];

    let result = Ext4Extent::parse(&data);

    assert!(result.is_ok());
}

#[test]
fn ignores_bytes_beyond_extent_size() {
    let mut data = [0u8; 16];

    data[0..4].copy_from_slice(&123u32.to_le_bytes());
    data[4..6].copy_from_slice(&3u16.to_le_bytes());
    data[8..12].copy_from_slice(&456u32.to_le_bytes());

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.logical_block(), 123);
    assert_eq!(extent.physical_block(), 456);
    assert_eq!(extent.length(), 3);
}

#[test]
fn calculates_last_logical_block() {
    let data = build_extent(100, 5, 0, 1000);

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.last_logical_block(), 104);
}

#[test]
fn calculates_last_physical_block() {
    let data = build_extent(100, 5, 0, 1000);

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.last_physical_block(), 1004);
}

#[test]
fn single_block_extent_has_same_first_and_last_block() {
    let data = build_extent(50, 1, 0, 500);

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.logical_block(), 50);
    assert_eq!(extent.last_logical_block(), 50);
    assert_eq!(extent.physical_block(), 500);
    assert_eq!(extent.last_physical_block(), 500);
}

#[test]
fn zero_length_extent_is_supported() {
    let data = build_extent(100, 0, 0, 1000);

    let extent = Ext4Extent::parse(&data).unwrap();

    assert_eq!(extent.length(), 0);
    assert_eq!(extent.last_logical_block(), 99);
    assert_eq!(extent.last_physical_block(), 999);
}

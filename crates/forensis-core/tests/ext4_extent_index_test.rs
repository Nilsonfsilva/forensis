use forensis_core::filesystem::ext4::Ext4ExtentIndex;

fn build_index(
    logical_block: u32,
    leaf_high: u16,
    leaf_low: u32,
) -> [u8; 12] {
    let mut data = [0u8; 12];

    data[0x00..0x04].copy_from_slice(&logical_block.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&leaf_low.to_le_bytes());
    data[0x08..0x0A].copy_from_slice(&leaf_high.to_le_bytes());

    data
}

#[test]
fn parses_valid_extent_index() {
    let data = build_index(100, 0x0001, 0x0000_2000);

    let index = Ext4ExtentIndex::parse(&data).unwrap();

    assert_eq!(index.logical_block(), 100);
    assert_eq!(index.leaf_block(), 0x0001_0000_2000);
}

#[test]
fn parses_zero_leaf_block() {
    let data = build_index(0, 0, 0);

    let index = Ext4ExtentIndex::parse(&data).unwrap();

    assert_eq!(index.logical_block(), 0);
    assert_eq!(index.leaf_block(), 0);
}

#[test]
fn parses_maximum_leaf_block() {
    let data = build_index(0xFFFF_FFFF, 0xFFFF, 0xFFFF_FFFF);

    let index = Ext4ExtentIndex::parse(&data).unwrap();

    assert_eq!(index.logical_block(), 0xFFFF_FFFF);
    assert_eq!(index.leaf_block(), 0xFFFF_FFFF_FFFF);
}

#[test]
fn combines_high_and_low_leaf_block_parts() {
    let data = build_index(500, 0x1234, 0x5678_9ABC);

    let index = Ext4ExtentIndex::parse(&data).unwrap();

    assert_eq!(index.leaf_block(), 0x1234_5678_9ABC);
}

#[test]
fn accepts_exact_index_size() {
    let data = [0u8; Ext4ExtentIndex::SIZE];

    let index = Ext4ExtentIndex::parse(&data).unwrap();

    assert_eq!(index.logical_block(), 0);
    assert_eq!(index.leaf_block(), 0);
}

#[test]
fn rejects_insufficient_data() {
    let data = [0u8; 11];

    let result = Ext4ExtentIndex::parse(&data);

    assert!(result.is_err());
}

#[test]
fn ignores_bytes_beyond_index_size() {
    let mut data = [0u8; 16];

    data[0x00..0x04].copy_from_slice(&123u32.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&456u32.to_le_bytes());
    data[0x08..0x0A].copy_from_slice(&789u16.to_le_bytes());

    data[0x0C..0x10].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

    let index = Ext4ExtentIndex::parse(&data).unwrap();

    assert_eq!(index.logical_block(), 123);
    assert_eq!(index.leaf_block(), 0x0315_0000_01C8);
}

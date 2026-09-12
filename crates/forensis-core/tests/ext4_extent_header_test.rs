use forensis_core::filesystem::ext4::Ext4ExtentHeader;

fn build_header(
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
) -> [u8; 12] {
    let mut data = [0u8; 12];

    data[0x00..0x02].copy_from_slice(&Ext4ExtentHeader::MAGIC.to_le_bytes());
    data[0x02..0x04].copy_from_slice(&entries.to_le_bytes());
    data[0x04..0x06].copy_from_slice(&max.to_le_bytes());
    data[0x06..0x08].copy_from_slice(&depth.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&generation.to_le_bytes());

    data
}

#[test]
fn parses_valid_extent_header() {
    let data = build_header(3, 4, 0, 12345);

    let header = Ext4ExtentHeader::parse(&data).unwrap();

    assert_eq!(header.magic(), Ext4ExtentHeader::MAGIC);
    assert_eq!(header.entries(), 3);
    assert_eq!(header.max(), 4);
    assert_eq!(header.depth(), 0);
    assert_eq!(header.generation(), 12345);
}

#[test]
fn identifies_leaf_node() {
    let data = build_header(2, 4, 0, 1);

    let header = Ext4ExtentHeader::parse(&data).unwrap();

    assert!(header.is_leaf());
    assert!(!header.is_index());
}

#[test]
fn identifies_index_node() {
    let data = build_header(2, 4, 1, 1);

    let header = Ext4ExtentHeader::parse(&data).unwrap();

    assert!(!header.is_leaf());
    assert!(header.is_index());
}

#[test]
fn accepts_zero_entries() {
    let data = build_header(0, 4, 0, 1);

    let header = Ext4ExtentHeader::parse(&data).unwrap();

    assert_eq!(header.entries(), 0);
    assert_eq!(header.max(), 4);
}

#[test]
fn accepts_entries_equal_to_maximum() {
    let data = build_header(4, 4, 0, 1);

    let header = Ext4ExtentHeader::parse(&data).unwrap();

    assert_eq!(header.entries(), 4);
    assert_eq!(header.max(), 4);
}

#[test]
fn rejects_invalid_magic() {
    let mut data = build_header(1, 4, 0, 1);

    data[0x00..0x02].copy_from_slice(&0x1234u16.to_le_bytes());

    let result = Ext4ExtentHeader::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_insufficient_data() {
    let data = [0u8; 11];

    let result = Ext4ExtentHeader::parse(&data);

    assert!(result.is_err());
}

#[test]
fn ignores_bytes_beyond_header() {
    let mut data = [0u8; 16];

    data[0x00..0x02].copy_from_slice(&Ext4ExtentHeader::MAGIC.to_le_bytes());
    data[0x02..0x04].copy_from_slice(&1u16.to_le_bytes());
    data[0x04..0x06].copy_from_slice(&4u16.to_le_bytes());
    data[0x06..0x08].copy_from_slice(&0u16.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&99u32.to_le_bytes());

    data[0x0C..0x10].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

    let header = Ext4ExtentHeader::parse(&data).unwrap();

    assert_eq!(header.entries(), 1);
    assert_eq!(header.max(), 4);
    assert_eq!(header.depth(), 0);
    assert_eq!(header.generation(), 99);
}

#[test]
fn rejects_entries_greater_than_maximum() {
    let data = build_header(5, 4, 0, 1);

    let result = Ext4ExtentHeader::parse(&data);

    assert!(result.is_err());
}

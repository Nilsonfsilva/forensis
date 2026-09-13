use forensis_core::filesystem::ext4::Ext4BlockGroupDescriptor;

#[test]
fn parses_valid_descriptor() {
    let mut data = [0u8; Ext4BlockGroupDescriptor::SIZE];

    data[0x00..0x04].copy_from_slice(&100u32.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&200u32.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&300u32.to_le_bytes());
    data[0x0C..0x0E].copy_from_slice(&400u16.to_le_bytes());
    data[0x0E..0x10].copy_from_slice(&500u16.to_le_bytes());
    data[0x10..0x12].copy_from_slice(&600u16.to_le_bytes());

    let descriptor = Ext4BlockGroupDescriptor::parse(&data)
        .expect("valid EXT4 block group descriptor should parse");

    assert_eq!(descriptor.block_bitmap(), 100);
    assert_eq!(descriptor.inode_bitmap(), 200);
    assert_eq!(descriptor.inode_table(), 300);
    assert_eq!(descriptor.free_blocks_count(), 400);
    assert_eq!(descriptor.free_inodes_count(), 500);
    assert_eq!(descriptor.used_dirs_count(), 600);
}

#[test]
fn rejects_insufficient_data() {
    let data = [0u8; Ext4BlockGroupDescriptor::SIZE - 1];

    let result = Ext4BlockGroupDescriptor::parse(&data);

    assert!(result.is_err());
}

#[test]
fn parses_zero_values() {
    let data = [0u8; Ext4BlockGroupDescriptor::SIZE];

    let descriptor = Ext4BlockGroupDescriptor::parse(&data)
        .expect("32 bytes should be enough to parse a descriptor");

    assert_eq!(descriptor.block_bitmap(), 0);
    assert_eq!(descriptor.inode_bitmap(), 0);
    assert_eq!(descriptor.inode_table(), 0);
    assert_eq!(descriptor.free_blocks_count(), 0);
    assert_eq!(descriptor.free_inodes_count(), 0);
    assert_eq!(descriptor.used_dirs_count(), 0);
}

#[test]
fn ignores_bytes_beyond_descriptor_size() {
    let mut data = [0u8; Ext4BlockGroupDescriptor::SIZE + 16];

    data[0x00..0x04].copy_from_slice(&1234u32.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&5678u32.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&9012u32.to_le_bytes());

    let descriptor = Ext4BlockGroupDescriptor::parse(&data)
        .expect("descriptor should parse from a larger buffer");

    assert_eq!(descriptor.block_bitmap(), 1234);
    assert_eq!(descriptor.inode_bitmap(), 5678);
    assert_eq!(descriptor.inode_table(), 9012);
}

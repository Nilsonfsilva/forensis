use forensis_core::filesystem::ext4::{Ext4BlockGroupDescriptor, Ext4BlockGroupTable};

fn create_descriptor(
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    free_blocks: u16,
    free_inodes: u16,
    used_dirs: u16,
) -> [u8; Ext4BlockGroupDescriptor::SIZE] {
    let mut data = [0u8; Ext4BlockGroupDescriptor::SIZE];

    data[0x00..0x04].copy_from_slice(&block_bitmap.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&inode_bitmap.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&inode_table.to_le_bytes());
    data[0x0C..0x0E].copy_from_slice(&free_blocks.to_le_bytes());
    data[0x0E..0x10].copy_from_slice(&free_inodes.to_le_bytes());
    data[0x10..0x12].copy_from_slice(&used_dirs.to_le_bytes());

    data
}

#[test]
fn parses_single_descriptor() {
    let data = create_descriptor(100, 200, 300, 400, 500, 600);

    let table =
        Ext4BlockGroupTable::parse(&data).expect("valid EXT4 block group table should parse");

    assert_eq!(table.len(), 1);
    assert!(!table.is_empty());

    let descriptor = table.get(0).expect("descriptor 0 should exist");

    assert_eq!(descriptor.block_bitmap(), 100);
    assert_eq!(descriptor.inode_bitmap(), 200);
    assert_eq!(descriptor.inode_table(), 300);
    assert_eq!(descriptor.free_blocks_count(), 400);
    assert_eq!(descriptor.free_inodes_count(), 500);
    assert_eq!(descriptor.used_dirs_count(), 600);
}

#[test]
fn parses_multiple_descriptors() {
    let descriptor0 = create_descriptor(100, 200, 300, 400, 500, 600);
    let descriptor1 = create_descriptor(1000, 2000, 3000, 4000, 5000, 6000);

    let mut data = Vec::new();
    data.extend_from_slice(&descriptor0);
    data.extend_from_slice(&descriptor1);

    let table = Ext4BlockGroupTable::parse(&data).expect("multiple valid descriptors should parse");

    assert_eq!(table.len(), 2);

    let first = table.get(0).expect("descriptor 0 should exist");
    let second = table.get(1).expect("descriptor 1 should exist");

    assert_eq!(first.block_bitmap(), 100);
    assert_eq!(first.inode_table(), 300);

    assert_eq!(second.block_bitmap(), 1000);
    assert_eq!(second.inode_table(), 3000);
}

#[test]
fn rejects_empty_table() {
    let data = [];

    let result = Ext4BlockGroupTable::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_invalid_table_size() {
    let data = [0u8; Ext4BlockGroupDescriptor::SIZE + 1];

    let result = Ext4BlockGroupTable::parse(&data);

    assert!(result.is_err());
}

#[test]
fn returns_none_for_out_of_range_index() {
    let data = create_descriptor(100, 200, 300, 400, 500, 600);

    let table =
        Ext4BlockGroupTable::parse(&data).expect("valid EXT4 block group table should parse");

    assert!(table.get(1).is_none());
    assert!(table.get(100).is_none());
}

#[test]
fn descriptors_returns_all_descriptors() {
    let descriptor0 = create_descriptor(100, 200, 300, 400, 500, 600);
    let descriptor1 = create_descriptor(1000, 2000, 3000, 4000, 5000, 6000);

    let mut data = Vec::new();
    data.extend_from_slice(&descriptor0);
    data.extend_from_slice(&descriptor1);

    let table =
        Ext4BlockGroupTable::parse(&data).expect("valid EXT4 block group table should parse");

    let descriptors = table.descriptors();

    assert_eq!(descriptors.len(), 2);
    assert_eq!(descriptors[0].block_bitmap(), 100);
    assert_eq!(descriptors[1].block_bitmap(), 1000);
}

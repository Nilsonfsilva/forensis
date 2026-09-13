use forensis_core::filesystem::ext4::{Ext4BlockGroupDescriptor, Ext4InodeLocator, Ext4Superblock};

fn build_superblock() -> Ext4Superblock {
    let mut data = [0u8; Ext4Superblock::SIZE];

    // 100000 inodes.
    data[0x00..0x04].copy_from_slice(&100000u32.to_le_bytes());

    // 1000000 blocks.
    data[0x04..0x08].copy_from_slice(&1000000u32.to_le_bytes());

    // 4096-byte blocks.
    data[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());

    // 8192 inodes per group.
    data[0x28..0x2C].copy_from_slice(&8192u32.to_le_bytes());

    // EXT4 magic.
    data[0x38..0x3A].copy_from_slice(&Ext4Superblock::EXT4_MAGIC.to_le_bytes());

    // 256-byte inodes.
    data[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());

    Ext4Superblock::parse(&data).expect("valid EXT4 superblock should parse")
}

fn build_descriptor(inode_table: u64) -> Ext4BlockGroupDescriptor {
    let mut data = [0u8; Ext4BlockGroupDescriptor::SIZE];

    data[0x08..0x10].copy_from_slice(&inode_table.to_le_bytes());

    Ext4BlockGroupDescriptor::parse(&data).expect("valid EXT4 block group descriptor should parse")
}

fn build_locator() -> Ext4InodeLocator {
    let superblock = build_superblock();

    Ext4InodeLocator::new(superblock, 256).expect("valid EXT4 inode locator should be created")
}

#[test]
fn creates_locator_with_valid_inode_size() {
    let locator = build_locator();

    assert_eq!(locator.inode_size(), 256);
}

#[test]
fn rejects_zero_inode_size() {
    let superblock = build_superblock();

    let result = Ext4InodeLocator::new(superblock, 0);

    assert!(result.is_err());
}

#[test]
fn rejects_non_power_of_two_inode_size() {
    let superblock = build_superblock();

    let result = Ext4InodeLocator::new(superblock, 192);

    assert!(result.is_err());
}

#[test]
fn rejects_inode_size_smaller_than_minimum() {
    let superblock = build_superblock();

    let result = Ext4InodeLocator::new(superblock, 64);

    assert!(result.is_err());
}

#[test]
fn inode_one_belongs_to_first_group() {
    let locator = build_locator();

    assert_eq!(locator.group_for_inode(1).unwrap(), 0);
    assert_eq!(locator.index_in_group(1).unwrap(), 0);
}

#[test]
fn last_inode_of_group_belongs_to_same_group() {
    let locator = build_locator();

    assert_eq!(locator.group_for_inode(8192).unwrap(), 0);
    assert_eq!(locator.index_in_group(8192).unwrap(), 8191);
}

#[test]
fn first_inode_of_second_group_belongs_to_second_group() {
    let locator = build_locator();

    assert_eq!(locator.group_for_inode(8193).unwrap(), 1);
    assert_eq!(locator.index_in_group(8193).unwrap(), 0);
}

#[test]
fn rejects_inode_number_zero() {
    let locator = build_locator();

    assert!(locator.group_for_inode(0).is_err());
    assert!(locator.index_in_group(0).is_err());
}

#[test]
fn calculates_inode_offset_inside_inode_table() {
    let locator = build_locator();

    // Group 0 inode table starts at filesystem block 100.
    //
    // Block size = 4096.
    // Inode 2 has index 1.
    // Inode size = 256.
    //
    // Table offset = 100 * 4096 = 409600.
    // Inode offset = 1 * 256 = 256.
    // Final offset = 409856.
    let offset = locator
        .inode_offset(2, 100)
        .expect("inode offset should be calculated");

    assert_eq!(offset, 409856);
}

#[test]
fn calculates_inode_block() {
    let locator = build_locator();

    // Inode 17:
    // index = 16
    // inode offset = 16 * 256 = 4096
    // inode table starts at block 100
    //
    // Therefore inode 17 starts at block 101.
    let block = locator
        .inode_block(17, 100)
        .expect("inode block should be calculated");

    assert_eq!(block, 101);
}

#[test]
fn calculates_offset_inside_block() {
    let locator = build_locator();

    // Inode 17 starts exactly at the beginning of block 101.
    let offset = locator
        .offset_inside_block(17)
        .expect("offset inside block should be calculated");

    assert_eq!(offset, 0);

    // Inode 18 starts 256 bytes into the block.
    let offset = locator
        .offset_inside_block(18)
        .expect("offset inside block should be calculated");

    assert_eq!(offset, 256);
}

#[test]
fn locates_inode_completely() {
    let locator = build_locator();
    let descriptor = build_descriptor(100);

    let (group, index, offset) = locator
        .locate(8193, &descriptor)
        .expect("inode should be located");

    assert_eq!(group, 1);
    assert_eq!(index, 0);
    assert_eq!(offset, 409600);
}

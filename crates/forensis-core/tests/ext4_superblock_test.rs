use forensis_core::filesystem::ext4::Ext4Superblock;

#[test]
fn parses_valid_superblock() {
    let mut data = [0u8; Ext4Superblock::SIZE];

    data[0x00..0x04].copy_from_slice(&1000u32.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&8000u32.to_le_bytes());
    data[0x0C..0x10].copy_from_slice(&3000u32.to_le_bytes());
    data[0x10..0x14].copy_from_slice(&100u32.to_le_bytes());
    data[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());

    // log_block_size = 2 -> 4096-byte blocks.
    data[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());

    data[0x20..0x24].copy_from_slice(&8192u32.to_le_bytes());
    data[0x28..0x2C].copy_from_slice(&2048u32.to_le_bytes());

    // EXT4 magic.
    data[0x38..0x3A].copy_from_slice(&Ext4Superblock::EXT4_MAGIC.to_le_bytes());

    // 256-byte inode.
    data[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());

    let superblock =
        Ext4Superblock::parse(&data).expect("valid EXT4 superblock should parse");

    assert_eq!(superblock.magic(), Ext4Superblock::EXT4_MAGIC);
    assert_eq!(superblock.inodes_count(), 1000);
    assert_eq!(superblock.blocks_count(), 8000);
    assert_eq!(superblock.free_blocks_count(), 3000);
    assert_eq!(superblock.free_inodes_count(), 100);
    assert_eq!(superblock.first_data_block(), 1);
    assert_eq!(superblock.block_size(), 4096);
    assert_eq!(superblock.blocks_per_group(), 8192);
    assert_eq!(superblock.inodes_per_group(), 2048);
    assert_eq!(superblock.inode_size(), 256);
}

#[test]
fn rejects_invalid_magic() {
    let mut data = [0u8; Ext4Superblock::SIZE];

    data[0x38..0x3A].copy_from_slice(&0x1234u16.to_le_bytes());
    data[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());

    let result = Ext4Superblock::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_insufficient_data() {
    let data = [0u8; Ext4Superblock::SIZE - 1];

    let result = Ext4Superblock::parse(&data);

    assert!(result.is_err());
}

#[test]
fn rejects_zero_inode_size() {
    let mut data = [0u8; Ext4Superblock::SIZE];

    data[0x38..0x3A].copy_from_slice(&Ext4Superblock::EXT4_MAGIC.to_le_bytes());

    let result = Ext4Superblock::parse(&data);

    assert!(result.is_err());
}

#[test]
fn calculates_block_size() {
    let mut data = [0u8; Ext4Superblock::SIZE];

    data[0x38..0x3A].copy_from_slice(&Ext4Superblock::EXT4_MAGIC.to_le_bytes());
    data[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
    data[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());

    let superblock =
        Ext4Superblock::parse(&data).expect("valid EXT4 superblock should parse");

    assert_eq!(superblock.block_size(), 4096);
}

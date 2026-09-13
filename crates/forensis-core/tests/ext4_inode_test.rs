use forensis_core::filesystem::ext4::Ext4Inode;

fn build_inode() -> [u8; 128] {
    let mut data = [0u8; 128];

    data[0x00..0x02].copy_from_slice(&0x81A4u16.to_le_bytes());
    data[0x02..0x04].copy_from_slice(&1000u16.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&12345u32.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&100u32.to_le_bytes());
    data[0x0C..0x10].copy_from_slice(&200u32.to_le_bytes());
    data[0x10..0x14].copy_from_slice(&300u32.to_le_bytes());
    data[0x14..0x18].copy_from_slice(&400u32.to_le_bytes());
    data[0x18..0x1A].copy_from_slice(&1001u16.to_le_bytes());
    data[0x1A..0x1C].copy_from_slice(&2u16.to_le_bytes());
    data[0x1C..0x20].copy_from_slice(&24u32.to_le_bytes());
    data[0x20..0x24].copy_from_slice(&0x00000001u32.to_le_bytes());

    data
}

#[test]
fn parses_valid_inode() {
    let data = build_inode();

    let inode = Ext4Inode::parse(&data).unwrap();

    assert_eq!(inode.mode(), 0x81A4);
    assert_eq!(inode.uid(), 1000);
    assert_eq!(inode.size(), 12345);
    assert_eq!(inode.atime(), 100);
    assert_eq!(inode.ctime(), 200);
    assert_eq!(inode.mtime(), 300);
    assert_eq!(inode.dtime(), 400);
    assert_eq!(inode.gid(), 1001);
    assert_eq!(inode.links_count(), 2);
    assert_eq!(inode.blocks(), 24);
    assert_eq!(inode.flags(), 1);
}

#[test]
fn rejects_insufficient_data() {
    let data = [0u8; 127];

    let result = Ext4Inode::parse(&data);

    assert!(result.is_err());
}

#[test]
fn accepts_exact_minimum_size() {
    let data = [0u8; 128];

    let result = Ext4Inode::parse(&data);

    assert!(result.is_ok());
}

#[test]
fn identifies_regular_file() {
    let mut data = [0u8; 128];

    data[0x00..0x02].copy_from_slice(&0x8000u16.to_le_bytes());

    let inode = Ext4Inode::parse(&data).unwrap();

    assert!(inode.is_regular_file());
    assert!(!inode.is_directory());
    assert!(!inode.is_symlink());
}

#[test]
fn identifies_directory() {
    let mut data = [0u8; 128];

    data[0x00..0x02].copy_from_slice(&0x4000u16.to_le_bytes());

    let inode = Ext4Inode::parse(&data).unwrap();

    assert!(inode.is_directory());
    assert!(!inode.is_regular_file());
    assert!(!inode.is_symlink());
}

#[test]
fn identifies_symbolic_link() {
    let mut data = [0u8; 128];

    data[0x00..0x02].copy_from_slice(&0xA000u16.to_le_bytes());

    let inode = Ext4Inode::parse(&data).unwrap();

    assert!(inode.is_symlink());
    assert!(!inode.is_regular_file());
    assert!(!inode.is_directory());
}

#[test]
fn rejects_unknown_file_type() {
    let mut data = [0u8; 128];

    data[0x00..0x02].copy_from_slice(&0x2000u16.to_le_bytes());

    let inode = Ext4Inode::parse(&data).unwrap();

    assert!(!inode.is_regular_file());
    assert!(!inode.is_directory());
    assert!(!inode.is_symlink());
}

#[test]
fn parses_i_block() {
    let mut data = [0u8; 128];

    for (index, byte) in data[0x28..0x64].iter_mut().enumerate() {
        *byte = index as u8;
    }

    let inode = Ext4Inode::parse(&data).unwrap();

    assert_eq!(inode.i_block().len(), 60);
    assert_eq!(inode.i_block()[0], 0);
    assert_eq!(inode.i_block()[1], 1);
    assert_eq!(inode.i_block()[30], 30);
    assert_eq!(inode.i_block()[59], 59);
}

#[test]
fn i_block_is_zero_when_not_initialized() {
    let data = [0u8; 128];

    let inode = Ext4Inode::parse(&data).unwrap();

    assert_eq!(inode.i_block(), &[0u8; 60]);
}

#[test]
fn i_block_preserves_raw_bytes() {
    let mut data = [0u8; 128];

    data[0x28..0x2C].copy_from_slice(&10u32.to_le_bytes());
    data[0x2C..0x30].copy_from_slice(&20u32.to_le_bytes());
    data[0x30..0x34].copy_from_slice(&30u32.to_le_bytes());

    let inode = Ext4Inode::parse(&data).unwrap();

    assert_eq!(&inode.i_block()[0..4], &10u32.to_le_bytes());

    assert_eq!(&inode.i_block()[4..8], &20u32.to_le_bytes());

    assert_eq!(&inode.i_block()[8..12], &30u32.to_le_bytes());
}

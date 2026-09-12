use forensis_core::filesystem::ext4::Ext4InodeTable;

#[test]
fn parses_valid_inode_table() {
    let data = [0u8; 256];

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert_eq!(table.inode_size(), 128);
    assert_eq!(table.inode_count(), 2);
    assert_eq!(table.size(), 256);
}

#[test]
fn rejects_empty_table() {
    let result = Ext4InodeTable::parse(&[], 128);

    assert!(result.is_err());
}

#[test]
fn rejects_zero_inode_size() {
    let data = [0u8; 128];

    let result = Ext4InodeTable::parse(&data, 0);

    assert!(result.is_err());
}

#[test]
fn rejects_inode_size_larger_than_table() {
    let data = [0u8; 128];

    let result = Ext4InodeTable::parse(&data, 256);

    assert!(result.is_err());
}

#[test]
fn rejects_incomplete_inode_data() {
    let data = [0u8; 200];

    let result = Ext4InodeTable::parse(&data, 128);

    assert!(result.is_err());
}

#[test]
fn returns_inode_bytes_by_index() {
    let mut data = [0u8; 256];

    data[0] = 0x11;
    data[128] = 0x22;

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert_eq!(table.inode(0).unwrap()[0], 0x11);
    assert_eq!(table.inode(1).unwrap()[0], 0x22);
}

#[test]
fn rejects_inode_index_out_of_bounds() {
    let data = [0u8; 256];

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert!(table.inode(2).is_err());
}

#[test]
fn calculates_inode_offsets() {
    let data = [0u8; 384];

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert_eq!(table.inode_offset(0).unwrap(), 0);
    assert_eq!(table.inode_offset(1).unwrap(), 128);
    assert_eq!(table.inode_offset(2).unwrap(), 256);
}

#[test]
fn rejects_inode_offset_out_of_bounds() {
    let data = [0u8; 256];

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert!(table.inode_offset(2).is_err());
}

#[test]
fn reports_contained_indexes() {
    let data = [0u8; 256];

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert!(table.contains(0));
    assert!(table.contains(1));
    assert!(!table.contains(2));
}

#[test]
fn returns_raw_table() {
    let data = [0x11u8; 256];

    let table = Ext4InodeTable::parse(&data, 128).unwrap();

    assert_eq!(table.raw(), &data);
}

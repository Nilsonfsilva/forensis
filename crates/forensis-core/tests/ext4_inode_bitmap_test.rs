use forensis_core::filesystem::ext4::Ext4InodeBitmap;

#[test]
fn parses_valid_bitmap() {
    let data = [0b0000_0001u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.inode_count(), 8);
    assert_eq!(bitmap.raw(), &data);
}

#[test]
fn rejects_empty_bitmap() {
    let result = Ext4InodeBitmap::parse(&[]);

    assert!(result.is_err());
}

#[test]
fn inode_numbers_are_one_based() {
    let data = [0b0000_0101u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    // Bit 0 represents inode 1.
    assert!(bitmap.is_allocated(1));

    // Bit 1 represents inode 2.
    assert!(!bitmap.is_allocated(2));

    // Bit 2 represents inode 3.
    assert!(bitmap.is_allocated(3));

    // Bit 3 represents inode 4.
    assert!(!bitmap.is_allocated(4));
}

#[test]
fn inode_zero_is_not_allocated() {
    let data = [0xFFu8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert!(!bitmap.is_allocated(0));
    assert!(bitmap.is_free(0));
}

#[test]
fn detects_free_inodes() {
    let data = [0b0000_0101u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert!(!bitmap.is_free(1));
    assert!(bitmap.is_free(2));
    assert!(!bitmap.is_free(3));
    assert!(bitmap.is_free(4));
}

#[test]
fn handles_bits_across_byte_boundary() {
    let data = [0b1000_0000u8, 0b0000_0001u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    // Bit 7 represents inode 8.
    assert!(bitmap.is_allocated(8));

    // Bit 0 of the second byte represents inode 9.
    assert!(bitmap.is_allocated(9));

    assert!(!bitmap.is_allocated(7));
    assert!(!bitmap.is_allocated(10));
}

#[test]
fn returns_false_for_inode_outside_bitmap() {
    let data = [0b0000_0001u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert!(!bitmap.is_allocated(9));
    assert!(bitmap.is_free(9));
}

#[test]
fn counts_allocated_inodes() {
    let data = [0b1010_0101u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.allocated_count(), 4);
}

#[test]
fn counts_free_inodes() {
    let data = [0b1010_0101u8];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.inode_count(), 8);
    assert_eq!(bitmap.allocated_count(), 4);
    assert_eq!(bitmap.free_count(), 4);
}

#[test]
fn reports_bitmap_size() {
    let data = [0u8; 4];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.size(), 4);
    assert_eq!(bitmap.inode_count(), 32);
}

#[test]
fn returns_raw_bitmap() {
    let data = [0xAA, 0x55, 0xFF];

    let bitmap = Ext4InodeBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.raw(), &data);
}

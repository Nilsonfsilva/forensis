use forensis_core::filesystem::ext4::Ext4BlockBitmap;

#[test]
fn parses_valid_bitmap() {
    let data = [0b0000_0001u8];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.block_count(), 8);
    assert_eq!(bitmap.raw(), &data);
}

#[test]
fn rejects_empty_bitmap() {
    let result = Ext4BlockBitmap::parse(&[]);

    assert!(result.is_err());
}

#[test]
fn detects_allocated_blocks() {
    let data = [0b0000_0101u8];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert!(bitmap.is_allocated(0));
    assert!(!bitmap.is_allocated(1));
    assert!(bitmap.is_allocated(2));
    assert!(!bitmap.is_allocated(3));
}

#[test]
fn detects_free_blocks() {
    let data = [0b0000_0101u8];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert!(bitmap.is_free(1));
    assert!(bitmap.is_free(3));
    assert!(!bitmap.is_free(0));
    assert!(!bitmap.is_free(2));
}

#[test]
fn handles_bits_across_byte_boundary() {
    let data = [0b1000_0000u8, 0b0000_0001u8];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert!(bitmap.is_allocated(7));
    assert!(bitmap.is_allocated(8));

    assert!(!bitmap.is_allocated(6));
    assert!(!bitmap.is_allocated(9));
}

#[test]
fn returns_false_for_block_outside_bitmap() {
    let data = [0b0000_0001u8];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert!(!bitmap.is_allocated(8));
    assert!(bitmap.is_free(8));
}

#[test]
fn reports_block_count() {
    let data = [0u8; 4];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.block_count(), 32);
}

#[test]
fn returns_raw_bitmap() {
    let data = [0xAA, 0x55, 0xFF];

    let bitmap = Ext4BlockBitmap::parse(&data).unwrap();

    assert_eq!(bitmap.raw(), &data);
}

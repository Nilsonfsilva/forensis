use forensis_core::filesystem::ntfs::FileNameAttribute;

#[test]
fn test_parse_file_name() {
    let name = "documento.txt";

    let name_utf16: Vec<u16> = name.encode_utf16().collect();

    /*
     * ---------------------------------------------------------
     * FILE_NAME VALUE
     * ---------------------------------------------------------
     *
     * Fixed portion = 66 bytes.
     */

    let value_length = 66 + name_utf16.len() * 2;

    /*
     * ---------------------------------------------------------
     * COMPLETE NTFS ATTRIBUTE
     * ---------------------------------------------------------
     *
     * Resident attribute header = 24 bytes.
     *
     * Attribute:
     *
     *   0x00 -> type
     *   0x04 -> length
     *   0x08 -> resident flag
     *   ...
     *   0x10 -> value length
     *   0x14 -> value offset
     */

    let value_offset = 24usize;

    let attribute_length = value_offset + value_length;

    let mut data = vec![0u8; attribute_length];

    /*
     * ---------------------------------------------------------
     * ATTRIBUTE HEADER
     * ---------------------------------------------------------
     */

    // Attribute type = $FILE_NAME (0x30).
    data[0..4].copy_from_slice(&0x30u32.to_le_bytes());

    // Attribute length.
    data[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());

    // Resident attribute.
    data[8] = 0;

    // Attribute name length = 0.
    data[9] = 0;

    // Attribute name offset.
    data[10..12].copy_from_slice(&0u16.to_le_bytes());

    // Attribute flags.
    data[12..14].copy_from_slice(&0u16.to_le_bytes());

    // Attribute ID.
    data[14..16].copy_from_slice(&0u16.to_le_bytes());

    /*
     * Resident value length.
     */

    data[16..20].copy_from_slice(&(value_length as u32).to_le_bytes());

    /*
     * Resident value offset.
     */

    data[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes());

    /*
     * ---------------------------------------------------------
     * FILE_NAME VALUE
     * ---------------------------------------------------------
     */

    let value = value_offset;

    /*
     * Parent directory reference.
     *
     * MFT record = 5
     * Sequence = 1
     *
     * Complete reference:
     *
     *     0x0001_0000_0000_0005
     */

    let parent_reference = (1u64 << 48) | 5u64;

    data[value..value + 8].copy_from_slice(&parent_reference.to_le_bytes());

    /*
     * Allocated size.
     */

    data[value + 40..value + 48].copy_from_slice(&4096u64.to_le_bytes());

    /*
     * Real size.
     */

    data[value + 48..value + 56].copy_from_slice(&1234u64.to_le_bytes());

    /*
     * File attributes.
     *
     * 0x20 = ARCHIVE
     */

    data[value + 56..value + 60].copy_from_slice(&0x20u32.to_le_bytes());

    /*
     * Filename length.
     */

    data[value + 64] = name_utf16.len() as u8;

    /*
     * Namespace = Win32.
     */

    data[value + 65] = 1u8;

    /*
     * Filename UTF-16LE.
     */

    for (index, character) in name_utf16.iter().enumerate() {
        let offset = value + 66 + index * 2;

        data[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }

    /*
     * ---------------------------------------------------------
     * PARSE
     * ---------------------------------------------------------
     */

    let parsed = FileNameAttribute::parse(&data).expect("FILE_NAME should be parsed");

    /*
     * ---------------------------------------------------------
     * VALIDATION
     * ---------------------------------------------------------
     */

    assert_eq!(parsed.parent_record, 5);

    assert_eq!(parsed.parent_sequence, 1);

    assert_eq!(parsed.namespace, 1);

    assert_eq!(parsed.allocated_size, 4096);

    assert_eq!(parsed.real_size, 1234);

    assert_eq!(parsed.file_attributes, 0x20);

    assert_eq!(parsed.name, "documento.txt");

    assert!(parsed.is_file());

    assert!(!parsed.is_directory());
}

#[test]
fn test_rejects_short_file_name() {
    let data = vec![0u8; 65];

    let result = FileNameAttribute::parse_value(&data);

    assert!(result.is_err());
}

#[test]
fn test_rejects_name_larger_than_buffer() {
    let mut data = vec![0u8; 66];

    /*
     * Declares 10 UTF-16 characters,
     * but the buffer contains no room
     * for the filename.
     */

    data[64] = 10;

    let result = FileNameAttribute::parse_value(&data);

    assert!(result.is_err());
}

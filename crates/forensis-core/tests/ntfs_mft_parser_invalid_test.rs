use forensis_core::filesystem::ntfs::{MftParser, MftRecord};

fn create_test_mft_record() -> Vec<u8> {
    let mut data = vec![0u8; 1024];

    // MFT record signature.
    data[0..4].copy_from_slice(b"FILE");

    // Update Sequence Array.
    let usa_offset = 48u16;
    let usa_count = 3u16;
    let update_sequence = 0xAAAAu16;

    data[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    data[6..8].copy_from_slice(&usa_count.to_le_bytes());

    data[48..50].copy_from_slice(&update_sequence.to_le_bytes());

    // Original sector trailer values.
    data[50..52].copy_from_slice(&0x1111u16.to_le_bytes());
    data[52..54].copy_from_slice(&0x2222u16.to_le_bytes());

    // NTFS stores the update sequence number at the end of
    // each 512-byte sector.
    data[510..512].copy_from_slice(&update_sequence.to_le_bytes());
    data[1022..1024].copy_from_slice(&update_sequence.to_le_bytes());

    data
}

#[test]
fn test_mft_parser_rejects_invalid_first_attribute_offset() {
    let mut data = create_test_mft_record();

    // First attribute offset = 2000,
    // beyond the available record.
    data[20..22].copy_from_slice(&2000u16.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be created");

    let result = MftParser::parse(&mut record);

    assert!(
        result.is_err(),
        "Parser should reject an invalid attribute offset"
    );
}

#[test]
fn test_mft_parser_rejects_truncated_attribute() {
    let mut data = create_test_mft_record();

    // First attribute starts at offset 56.
    data[20..22].copy_from_slice(&56u16.to_le_bytes());

    let attribute_offset = 56;

    // STANDARD_INFORMATION.
    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x10u32.to_le_bytes());

    // Claim 500 bytes, although the attribute
    // does not actually exist in the remaining buffer.
    data[attribute_offset + 4..attribute_offset + 8].copy_from_slice(&500u32.to_le_bytes());

    // Resident.
    data[attribute_offset + 8] = 0;

    let mut record = MftRecord::new(0, data).expect("MFT record should be created");

    let result = MftParser::parse(&mut record);

    assert!(
        result.is_err(),
        "Parser should reject a truncated attribute"
    );
}

#[test]
fn test_mft_parser_rejects_invalid_attribute_length() {
    let mut data = create_test_mft_record();

    // First attribute starts at offset 56.
    data[20..22].copy_from_slice(&56u16.to_le_bytes());

    let attribute_offset = 56;

    // STANDARD_INFORMATION.
    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x10u32.to_le_bytes());

    // Attribute length smaller than the
    // minimum NTFS attribute header.
    data[attribute_offset + 4..attribute_offset + 8].copy_from_slice(&8u32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be created");

    let result = MftParser::parse(&mut record);

    assert!(
        result.is_err(),
        "Parser should reject an invalid attribute length"
    );
}

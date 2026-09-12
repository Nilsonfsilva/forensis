use forensis_core::filesystem::{AttributeType, MftAttribute};

#[test]
fn test_parse_standard_information_attribute() {
    let mut data = vec![0u8; 60];

    // ---------------------------------------------------------
    // Attribute header
    // ---------------------------------------------------------

    // Type = $STANDARD_INFORMATION
    data[0..4].copy_from_slice(&0x10u32.to_le_bytes());

    // Attribute length = 60
    data[4..8].copy_from_slice(&60u32.to_le_bytes());

    // Resident attribute
    data[8] = 0;

    // Attribute ID
    data[14..16].copy_from_slice(&1u16.to_le_bytes());

    // Value length = 36
    data[16..20].copy_from_slice(&36u32.to_le_bytes());

    // Value offset = 24
    data[20..22].copy_from_slice(&24u16.to_le_bytes());

    // ---------------------------------------------------------
    // Parse
    // ---------------------------------------------------------

    let attribute = MftAttribute::parse(&data).expect("failed to parse attribute");

    // ---------------------------------------------------------
    // Validate
    // ---------------------------------------------------------

    assert_eq!(attribute.attribute_type, AttributeType::StandardInformation);

    assert_eq!(attribute.length, 60);

    assert_eq!(attribute.data.len(), 36);
}

#[test]
fn test_parse_data_attribute() {
    let mut data = vec![0u8; 32];

    // ---------------------------------------------------------
    // Attribute header
    // ---------------------------------------------------------

    // Type = $DATA
    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    // Attribute length = 32
    data[4..8].copy_from_slice(&32u32.to_le_bytes());

    // Resident attribute
    data[8] = 0;

    // Attribute ID
    data[14..16].copy_from_slice(&1u16.to_le_bytes());

    // Value length = 8
    data[16..20].copy_from_slice(&8u32.to_le_bytes());

    // Value offset = 24
    data[20..22].copy_from_slice(&24u16.to_le_bytes());

    // ---------------------------------------------------------
    // DATA value
    // ---------------------------------------------------------

    data[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    // ---------------------------------------------------------
    // Parse
    // ---------------------------------------------------------

    let attribute = MftAttribute::parse(&data).expect("failed to parse attribute");

    // ---------------------------------------------------------
    // Validate
    // ---------------------------------------------------------

    assert_eq!(attribute.attribute_type, AttributeType::Data);

    assert_eq!(attribute.length, 32);

    assert_eq!(attribute.data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn test_parse_rejects_short_attribute() {
    let data = vec![0u8; 7];

    let result = MftAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_rejects_zero_length_attribute() {
    let mut data = vec![0u8; 16];

    data[0..4].copy_from_slice(&0x10u32.to_le_bytes());

    data[4..8].copy_from_slice(&0u32.to_le_bytes());

    let result = MftAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_rejects_attribute_larger_than_buffer() {
    let mut data = vec![0u8; 32];

    data[0..4].copy_from_slice(&0x10u32.to_le_bytes());

    data[4..8].copy_from_slice(&64u32.to_le_bytes());

    let result = MftAttribute::parse(&data);

    assert!(result.is_err());
}

#[test]
fn test_parse_end_attribute() {
    let mut data = vec![0u8; 16];

    data[0..4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let attribute = MftAttribute::parse(&data).expect("failed to parse end attribute");

    assert_eq!(attribute.attribute_type, AttributeType::End);
}

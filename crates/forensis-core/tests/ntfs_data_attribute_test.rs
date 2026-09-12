use forensis_core::filesystem::ntfs::{AttributeType, MftAttribute};

#[test]
fn test_parse_resident_data_attribute() {
    /*
     * NTFS resident $DATA attribute.
     *
     * Header:
     *   16 bytes common header
     *
     * Resident extension:
     *   4 bytes  value length
     *   2 bytes  value offset
     *   1 byte   flags
     *   1 byte   reserved
     *
     * Total header:
     *   24 bytes
     *
     * Value:
     *   5 bytes
     *
     * Total attribute:
     *   29 bytes
     */

    let mut data = vec![0u8; 29];

    // ---------------------------------------------------------
    // Attribute type = $DATA (0x80)
    // ---------------------------------------------------------

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    // ---------------------------------------------------------
    // Attribute length = 29 bytes
    // ---------------------------------------------------------

    data[4..8].copy_from_slice(&29u32.to_le_bytes());

    // ---------------------------------------------------------
    // Resident attribute
    // ---------------------------------------------------------

    data[8] = 0;

    // ---------------------------------------------------------
    // Attribute ID
    // ---------------------------------------------------------

    data[14..16].copy_from_slice(&1u16.to_le_bytes());

    // ---------------------------------------------------------
    // Value length = 5 bytes
    // ---------------------------------------------------------

    data[16..20].copy_from_slice(&5u32.to_le_bytes());

    // ---------------------------------------------------------
    // Value offset = 24
    // ---------------------------------------------------------

    data[20..22].copy_from_slice(&24u16.to_le_bytes());

    // ---------------------------------------------------------
    // DATA value
    // ---------------------------------------------------------

    data[24..29].copy_from_slice(b"hello");

    // ---------------------------------------------------------
    // Parse
    // ---------------------------------------------------------

    let attribute = MftAttribute::parse(&data).expect("DATA attribute should be valid");

    // ---------------------------------------------------------
    // Validate
    // ---------------------------------------------------------

    assert_eq!(attribute.attribute_type, AttributeType::Data);

    assert!(!attribute.non_resident);

    assert_eq!(attribute.id, 1);

    assert_eq!(attribute.length, 29);

    assert_eq!(attribute.data, b"hello");
}

#[test]
fn test_parse_non_resident_data_attribute() {
    /*
     * Minimal non-resident $DATA attribute.
     *
     * The actual file data is not stored directly in
     * the attribute. It will later be interpreted through
     * the NTFS data runs / runlist.
     */

    let mut data = vec![0u8; 64];

    // ---------------------------------------------------------
    // Attribute type = $DATA
    // ---------------------------------------------------------

    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

    // ---------------------------------------------------------
    // Attribute length
    // ---------------------------------------------------------

    data[4..8].copy_from_slice(&64u32.to_le_bytes());

    // ---------------------------------------------------------
    // Non-resident flag
    // ---------------------------------------------------------

    data[8] = 1;

    // ---------------------------------------------------------
    // Attribute ID
    // ---------------------------------------------------------

    data[14..16].copy_from_slice(&2u16.to_le_bytes());

    // ---------------------------------------------------------
    // Parse
    // ---------------------------------------------------------

    let attribute =
        MftAttribute::parse(&data).expect("Non-resident DATA attribute should be valid");

    // ---------------------------------------------------------
    // Validate
    // ---------------------------------------------------------

    assert_eq!(attribute.attribute_type, AttributeType::Data);

    assert!(attribute.non_resident);

    assert_eq!(attribute.id, 2);

    assert_eq!(attribute.length, 64);

    /*
     * Non-resident attributes do not expose file data
     * directly at this stage.
     */
    assert!(attribute.data.is_empty());
}

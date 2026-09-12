use forensis_core::filesystem::ntfs::MftRecord;

#[test]
fn test_mft_record_applies_usa_fixup() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    let usa_offset = 48u16;
    let usa_count = 3u16;
    let update_sequence = 0xAAAAu16;

    data[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    data[6..8].copy_from_slice(&usa_count.to_le_bytes());

    data[usa_offset as usize..usa_offset as usize + 2]
        .copy_from_slice(&update_sequence.to_le_bytes());

    let first_replacement = 0x1122u16;
    let second_replacement = 0x3344u16;

    data[50..52].copy_from_slice(&first_replacement.to_le_bytes());
    data[52..54].copy_from_slice(&second_replacement.to_le_bytes());

    data[510..512].copy_from_slice(&update_sequence.to_le_bytes());
    data[1022..1024].copy_from_slice(&update_sequence.to_le_bytes());

    let record = MftRecord::new(65, data).expect("MFT record should be valid");

    assert_eq!(&record.raw()[510..512], &first_replacement.to_le_bytes());
    assert_eq!(&record.raw()[1022..1024], &second_replacement.to_le_bytes());
}

#[test]
fn test_mft_record_rejects_invalid_usa_sequence() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    let update_sequence = 0xAAAAu16;

    data[48..50].copy_from_slice(&update_sequence.to_le_bytes());

    data[50..52].copy_from_slice(&0x1122u16.to_le_bytes());
    data[52..54].copy_from_slice(&0x3344u16.to_le_bytes());

    data[510..512].copy_from_slice(&0xBBBBu16.to_le_bytes());
    data[1022..1024].copy_from_slice(&update_sequence.to_le_bytes());

    let result = MftRecord::new(65, data);

    assert!(result.is_err());
}

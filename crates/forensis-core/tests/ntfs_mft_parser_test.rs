use forensis_core::filesystem::ntfs::{MftParser, MftRecord};

#[test]
fn test_mft_parser_reads_record_header() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&42u16.to_le_bytes());
    data[18..20].copy_from_slice(&2u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&0x0001u16.to_le_bytes());

    data[24..28].copy_from_slice(&512u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&5u16.to_le_bytes());

    data[56..60].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    let header = record.header().expect("MFT header should be available");

    assert_eq!(header.usa_offset, 48);
    assert_eq!(header.usa_count, 3);
    assert_eq!(header.sequence_number, 42);
    assert_eq!(header.hard_link_count, 2);
    assert_eq!(header.first_attribute_offset, 56);
    assert_eq!(header.flags, 0x0001);
    assert_eq!(header.used_size, 512);
    assert_eq!(header.allocated_size, 1024);
    assert_eq!(header.base_record, 0);
    assert_eq!(header.next_attribute_id, 5);

    assert_eq!(parsed.index, 0);
    assert!(parsed.standard_information.is_none());
    assert!(parsed.file_names.is_empty());
    assert!(parsed.data.is_none());
}

#[test]
fn test_mft_parser_reads_standard_information() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&42u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&0x0001u16.to_le_bytes());

    data[24..28].copy_from_slice(&512u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&2u16.to_le_bytes());

    let attribute_offset = 56;

    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x10u32.to_le_bytes());

    data[attribute_offset + 4..attribute_offset + 8].copy_from_slice(&60u32.to_le_bytes());

    data[attribute_offset + 8] = 0;

    data[attribute_offset + 14..attribute_offset + 16].copy_from_slice(&1u16.to_le_bytes());

    data[attribute_offset + 16..attribute_offset + 20].copy_from_slice(&36u32.to_le_bytes());

    data[attribute_offset + 20..attribute_offset + 22].copy_from_slice(&24u16.to_le_bytes());

    let value_offset = attribute_offset + 24;

    data[value_offset..value_offset + 8].copy_from_slice(&100u64.to_le_bytes());

    data[value_offset + 8..value_offset + 16].copy_from_slice(&200u64.to_le_bytes());

    data[value_offset + 16..value_offset + 24].copy_from_slice(&300u64.to_le_bytes());

    data[value_offset + 24..value_offset + 32].copy_from_slice(&400u64.to_le_bytes());

    data[value_offset + 32..value_offset + 36].copy_from_slice(&0x20u32.to_le_bytes());

    let end_offset = attribute_offset + 60;

    data[end_offset..end_offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    let info = parsed
        .standard_information
        .expect("STANDARD_INFORMATION should be parsed");

    assert_eq!(info.creation_time, 100);
    assert_eq!(info.modification_time, 200);
    assert_eq!(info.mft_modification_time, 300);
    assert_eq!(info.access_time, 400);
    assert_eq!(info.file_attributes, 0x20);

    assert!(parsed.file_names.is_empty());
    assert!(parsed.data.is_none());
}

#[test]
fn test_mft_parser_reads_file_name() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&42u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&0x0001u16.to_le_bytes());

    data[24..28].copy_from_slice(&512u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&2u16.to_le_bytes());

    let attribute_offset = 56;

    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x30u32.to_le_bytes());

    let attribute_length = 106u32;

    data[attribute_offset + 4..attribute_offset + 8]
        .copy_from_slice(&attribute_length.to_le_bytes());

    data[attribute_offset + 8] = 0;

    data[attribute_offset + 14..attribute_offset + 16].copy_from_slice(&1u16.to_le_bytes());

    data[attribute_offset + 16..attribute_offset + 20].copy_from_slice(&82u32.to_le_bytes());

    data[attribute_offset + 20..attribute_offset + 22].copy_from_slice(&24u16.to_le_bytes());

    let value_offset = attribute_offset + 24;

    data[value_offset..value_offset + 8].copy_from_slice(&5u64.to_le_bytes());

    data[value_offset + 40..value_offset + 48].copy_from_slice(&4096u64.to_le_bytes());

    data[value_offset + 48..value_offset + 56].copy_from_slice(&1234u64.to_le_bytes());

    data[value_offset + 56..value_offset + 60].copy_from_slice(&0x20u32.to_le_bytes());

    data[value_offset + 64] = 8;
    data[value_offset + 65] = 1;

    for (index, character) in "test.txt".encode_utf16().enumerate() {
        let position = value_offset + 66 + index * 2;

        data[position..position + 2].copy_from_slice(&character.to_le_bytes());
    }

    let end_offset = attribute_offset + attribute_length as usize;

    data[end_offset..end_offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    assert_eq!(parsed.file_names.len(), 1);

    let file_name = &parsed.file_names[0];

    assert_eq!(file_name.parent_record, 5);
    assert_eq!(file_name.allocated_size, 4096);
    assert_eq!(file_name.real_size, 1234);
    assert_eq!(file_name.file_attributes, 0x20);
    assert_eq!(file_name.name, "test.txt");

    assert!(parsed.data.is_none());
}

#[test]
fn test_mft_parser_detects_data_attribute() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&0x0001u16.to_le_bytes());

    data[24..28].copy_from_slice(&512u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&2u16.to_le_bytes());

    let attribute_offset = 56;

    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x80u32.to_le_bytes());

    data[attribute_offset + 4..attribute_offset + 8].copy_from_slice(&60u32.to_le_bytes());

    data[attribute_offset + 8] = 0;

    data[attribute_offset + 14..attribute_offset + 16].copy_from_slice(&1u16.to_le_bytes());

    data[attribute_offset + 16..attribute_offset + 20].copy_from_slice(&4u32.to_le_bytes());

    data[attribute_offset + 20..attribute_offset + 22].copy_from_slice(&24u16.to_le_bytes());

    let value_offset = attribute_offset + 24;

    data[value_offset..value_offset + 4].copy_from_slice(b"TEST");

    let end_offset = attribute_offset + 60;

    data[end_offset..end_offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    assert!(parsed.data.is_some());
}

#[test]
fn test_mft_parser_reads_multiple_file_names() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&1u16.to_le_bytes());

    data[24..28].copy_from_slice(&256u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&3u16.to_le_bytes());

    let first = 56;

    data[first..first + 4].copy_from_slice(&0x30u32.to_le_bytes());

    data[first + 4..first + 8].copy_from_slice(&96u32.to_le_bytes());

    data[first + 8] = 0;

    data[first + 14..first + 16].copy_from_slice(&1u16.to_le_bytes());

    data[first + 16..first + 20].copy_from_slice(&72u32.to_le_bytes());

    data[first + 20..first + 22].copy_from_slice(&24u16.to_le_bytes());

    let first_value = first + 24;

    data[first_value..first_value + 8].copy_from_slice(&5u64.to_le_bytes());

    data[first_value + 40..first_value + 48].copy_from_slice(&100u64.to_le_bytes());

    data[first_value + 48..first_value + 56].copy_from_slice(&80u64.to_le_bytes());

    data[first_value + 56..first_value + 60].copy_from_slice(&0x20u32.to_le_bytes());

    data[first_value + 64] = 3;
    data[first_value + 65] = 1;

    for (i, c) in "foo".encode_utf16().enumerate() {
        data[first_value + 66 + i * 2..first_value + 68 + i * 2].copy_from_slice(&c.to_le_bytes());
    }

    let second = first + 96;

    data[second..second + 4].copy_from_slice(&0x30u32.to_le_bytes());

    data[second + 4..second + 8].copy_from_slice(&96u32.to_le_bytes());

    data[second + 8] = 0;

    data[second + 14..second + 16].copy_from_slice(&2u16.to_le_bytes());

    data[second + 16..second + 20].copy_from_slice(&72u32.to_le_bytes());

    data[second + 20..second + 22].copy_from_slice(&24u16.to_le_bytes());

    let second_value = second + 24;

    data[second_value..second_value + 8].copy_from_slice(&5u64.to_le_bytes());

    data[second_value + 40..second_value + 48].copy_from_slice(&100u64.to_le_bytes());

    data[second_value + 48..second_value + 56].copy_from_slice(&80u64.to_le_bytes());

    data[second_value + 56..second_value + 60].copy_from_slice(&0x20u32.to_le_bytes());

    data[second_value + 64] = 3;
    data[second_value + 65] = 1;

    for (i, c) in "bar".encode_utf16().enumerate() {
        data[second_value + 66 + i * 2..second_value + 68 + i * 2]
            .copy_from_slice(&c.to_le_bytes());
    }

    let end = second + 96;

    data[end..end + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    assert_eq!(parsed.file_names.len(), 2);
    assert_eq!(parsed.file_names[0].name, "foo");
    assert_eq!(parsed.file_names[1].name, "bar");
}

#[test]
fn test_mft_parser_preserves_multiple_data_runs() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&0x0001u16.to_le_bytes());

    data[24..28].copy_from_slice(&256u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&2u16.to_le_bytes());

    let attribute_offset = 56;

    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x80u32.to_le_bytes());

    let attribute_length = 72u32;

    data[attribute_offset + 4..attribute_offset + 8]
        .copy_from_slice(&attribute_length.to_le_bytes());

    data[attribute_offset + 8] = 1;

    data[attribute_offset + 14..attribute_offset + 16].copy_from_slice(&1u16.to_le_bytes());

    data[attribute_offset + 16..attribute_offset + 24].copy_from_slice(&0u64.to_le_bytes());

    data[attribute_offset + 24..attribute_offset + 32].copy_from_slice(&11u64.to_le_bytes());

    data[attribute_offset + 32..attribute_offset + 34].copy_from_slice(&64u16.to_le_bytes());

    data[attribute_offset + 34..attribute_offset + 36].copy_from_slice(&0u16.to_le_bytes());

    data[attribute_offset + 40..attribute_offset + 48].copy_from_slice(&49152u64.to_le_bytes());

    data[attribute_offset + 48..attribute_offset + 56].copy_from_slice(&32768u64.to_le_bytes());

    data[attribute_offset + 56..attribute_offset + 64].copy_from_slice(&32768u64.to_le_bytes());

    data[attribute_offset + 64] = 0x11;
    data[attribute_offset + 65] = 0x08;
    data[attribute_offset + 66] = 0x64;

    data[attribute_offset + 67] = 0x21;
    data[attribute_offset + 68] = 0x04;
    data[attribute_offset + 69] = 0x96;
    data[attribute_offset + 70] = 0x00;

    data[attribute_offset + 71] = 0x00;

    let end_of_attributes = attribute_offset + attribute_length as usize;

    data[end_of_attributes..end_of_attributes + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    let data_attribute = parsed.data.expect("$DATA attribute should be parsed");

    assert!(data_attribute.non_resident);
    assert_eq!(data_attribute.real_size, 32768);
    assert_eq!(data_attribute.data_runs.len(), 2);

    assert_eq!(data_attribute.data_runs[0].lcn, Some(100));
    assert_eq!(data_attribute.data_runs[0].cluster_count, 8);

    assert_eq!(data_attribute.data_runs[1].lcn, Some(250));
    assert_eq!(data_attribute.data_runs[1].cluster_count, 4);
}

#[test]
fn test_mft_parser_reads_combined_standard_information_file_name_and_data() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&1u16.to_le_bytes());

    data[24..28].copy_from_slice(&512u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&4u16.to_le_bytes());

    let standard = 56;

    data[standard..standard + 4].copy_from_slice(&0x10u32.to_le_bytes());

    data[standard + 4..standard + 8].copy_from_slice(&60u32.to_le_bytes());

    data[standard + 8] = 0;

    data[standard + 14..standard + 16].copy_from_slice(&1u16.to_le_bytes());

    data[standard + 16..standard + 20].copy_from_slice(&36u32.to_le_bytes());

    data[standard + 20..standard + 22].copy_from_slice(&24u16.to_le_bytes());

    let standard_value = standard + 24;

    data[standard_value..standard_value + 8].copy_from_slice(&100u64.to_le_bytes());

    data[standard_value + 8..standard_value + 16].copy_from_slice(&200u64.to_le_bytes());

    data[standard_value + 16..standard_value + 24].copy_from_slice(&300u64.to_le_bytes());

    data[standard_value + 24..standard_value + 32].copy_from_slice(&400u64.to_le_bytes());

    data[standard_value + 32..standard_value + 36].copy_from_slice(&0x20u32.to_le_bytes());

    let file_name = standard + 60;

    data[file_name..file_name + 4].copy_from_slice(&0x30u32.to_le_bytes());

    data[file_name + 4..file_name + 8].copy_from_slice(&114u32.to_le_bytes());

    data[file_name + 8] = 0;

    data[file_name + 14..file_name + 16].copy_from_slice(&2u16.to_le_bytes());

    data[file_name + 16..file_name + 20].copy_from_slice(&90u32.to_le_bytes());

    data[file_name + 20..file_name + 22].copy_from_slice(&24u16.to_le_bytes());

    let file_name_value = file_name + 24;

    data[file_name_value..file_name_value + 8].copy_from_slice(&5u64.to_le_bytes());

    data[file_name_value + 40..file_name_value + 48].copy_from_slice(&4096u64.to_le_bytes());

    data[file_name_value + 48..file_name_value + 56].copy_from_slice(&1234u64.to_le_bytes());

    data[file_name_value + 56..file_name_value + 60].copy_from_slice(&0x20u32.to_le_bytes());

    data[file_name_value + 64] = 12;
    data[file_name_value + 65] = 1;

    for (i, c) in "document.txt".encode_utf16().enumerate() {
        data[file_name_value + 66 + i * 2..file_name_value + 68 + i * 2]
            .copy_from_slice(&c.to_le_bytes());
    }

    let data_attribute = file_name + 114;

    data[data_attribute..data_attribute + 4].copy_from_slice(&0x80u32.to_le_bytes());

    data[data_attribute + 4..data_attribute + 8].copy_from_slice(&72u32.to_le_bytes());

    data[data_attribute + 8] = 1;

    data[data_attribute + 14..data_attribute + 16].copy_from_slice(&3u16.to_le_bytes());

    data[data_attribute + 16..data_attribute + 24].copy_from_slice(&0u64.to_le_bytes());

    data[data_attribute + 24..data_attribute + 32].copy_from_slice(&7u64.to_le_bytes());

    data[data_attribute + 32..data_attribute + 34].copy_from_slice(&64u16.to_le_bytes());

    data[data_attribute + 40..data_attribute + 48].copy_from_slice(&32768u64.to_le_bytes());

    data[data_attribute + 48..data_attribute + 56].copy_from_slice(&24576u64.to_le_bytes());

    data[data_attribute + 56..data_attribute + 64].copy_from_slice(&24576u64.to_le_bytes());

    data[data_attribute + 64] = 0x11;
    data[data_attribute + 65] = 0x08;
    data[data_attribute + 66] = 0x64;

    data[data_attribute + 67] = 0x00;

    let end = data_attribute + 72;

    data[end..end + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("MFT parser should succeed");

    let info = parsed
        .standard_information
        .expect("STANDARD_INFORMATION should exist");

    assert_eq!(info.creation_time, 100);
    assert_eq!(info.modification_time, 200);
    assert_eq!(info.mft_modification_time, 300);
    assert_eq!(info.access_time, 400);

    assert_eq!(parsed.file_names.len(), 1);
    assert_eq!(parsed.file_names[0].name, "document.txt");

    let parsed_data = parsed.data.expect("$DATA attribute should exist");

    assert!(parsed_data.non_resident);
    assert_eq!(parsed_data.real_size, 24576);
    assert_eq!(parsed_data.allocated_size, 32768);
    assert_eq!(parsed_data.data_runs.len(), 1);
    assert_eq!(parsed_data.data_runs[0].lcn, Some(100));
    assert_eq!(parsed_data.data_runs[0].cluster_count, 8);
}

#[test]
fn test_mft_parser_ignores_unknown_attribute() {
    let mut data = vec![0u8; 1024];

    data[0..4].copy_from_slice(b"FILE");

    data[4..6].copy_from_slice(&48u16.to_le_bytes());
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    data[20..22].copy_from_slice(&56u16.to_le_bytes());
    data[22..24].copy_from_slice(&1u16.to_le_bytes());

    data[24..28].copy_from_slice(&256u32.to_le_bytes());
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    data[32..40].copy_from_slice(&0u64.to_le_bytes());
    data[40..42].copy_from_slice(&2u16.to_le_bytes());

    // ---------------------------------------------------------
    // UNKNOWN ATTRIBUTE
    // ---------------------------------------------------------
    //
    // Minimal valid structure:
    //
    // type        = 4 bytes
    // length      = 24 bytes
    // resident    = 0
    // name length = 0
    // name offset = 0
    // flags       = 0
    // id          = 1
    //
    // The specific content does not matter because the parser
    // must simply ignore the unknown type.
    //
    let attribute = 56usize;

    data[attribute..attribute + 4].copy_from_slice(&0x99999999u32.to_le_bytes());

    data[attribute + 4..attribute + 8].copy_from_slice(&24u32.to_le_bytes());

    data[attribute + 8] = 0;

    data[attribute + 9] = 0;

    data[attribute + 10..attribute + 12].copy_from_slice(&0u16.to_le_bytes());

    data[attribute + 12..attribute + 14].copy_from_slice(&0u16.to_le_bytes());

    data[attribute + 14..attribute + 16].copy_from_slice(&1u16.to_le_bytes());

    // ---------------------------------------------------------
    // END OF ATTRIBUTES
    // ---------------------------------------------------------

    data[attribute + 24..attribute + 28].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    // ---------------------------------------------------------
    // PARSE
    // ---------------------------------------------------------

    let mut record = MftRecord::new(0, data).expect("MFT record should be valid");

    let parsed = MftParser::parse(&mut record).expect("Unknown attribute should not break parser");

    // ---------------------------------------------------------
    // VALIDATE
    // ---------------------------------------------------------

    assert!(parsed.standard_information.is_none());
    assert!(parsed.file_names.is_empty());
    assert!(parsed.data.is_none());
}

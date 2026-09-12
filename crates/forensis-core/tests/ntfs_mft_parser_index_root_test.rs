use forensis_core::filesystem::{MftParser, MftRecord};

fn create_mft_record_with_index_root() -> MftRecord {
    let mut data = vec![0u8; 1024];

    /*
     * ---------------------------------------------------------
     * MFT RECORD HEADER
     * ---------------------------------------------------------
     */

    /*
     * MFT record signature.
     *
     * Every valid NTFS MFT record begins with:
     *
     * 46 49 4C 45
     *
     * ASCII:
     *
     * F I L E
     */
    data[0..4].copy_from_slice(b"FILE");

    /*
     * Update Sequence Array offset.
     */
    data[4..6].copy_from_slice(&48u16.to_le_bytes());

    /*
     * Update Sequence Array count.
     */
    data[6..8].copy_from_slice(&3u16.to_le_bytes());

    /*
     * Sequence number.
     */
    data[16..18].copy_from_slice(&1u16.to_le_bytes());

    /*
     * Hard link count.
     */
    data[18..20].copy_from_slice(&1u16.to_le_bytes());

    /*
     * First attribute starts at offset 56.
     */
    data[20..22].copy_from_slice(&56u16.to_le_bytes());

    /*
     * Record flags:
     *
     * 0x0003 =
     *
     * 0x0001 = record in use
     * 0x0002 = directory
     */
    data[22..24].copy_from_slice(&0x0003u16.to_le_bytes());

    /*
     * Used size.
     */
    data[24..28].copy_from_slice(&200u32.to_le_bytes());

    /*
     * Allocated size.
     */
    data[28..32].copy_from_slice(&1024u32.to_le_bytes());

    /*
     * Base record reference.
     */
    data[32..40].copy_from_slice(&0u64.to_le_bytes());

    /*
     * Next attribute ID.
     */
    data[40..42].copy_from_slice(&1u16.to_le_bytes());

    /*
     * ---------------------------------------------------------
     * INDEX_ROOT VALUE
     * ---------------------------------------------------------
     *
     * INDEX_ROOT header:
     *
     * 00..04 = indexed attribute type
     * 04..08 = collation rule
     * 08..12 = index block size
     * 12..16 = clusters per index block
     *
     * INDEX_HEADER:
     *
     * 16..20 = offset to first entry
     * 20..24 = total size
     * 24..28 = allocated size
     * 28..32 = flags
     */

    let mut index_root = vec![0u8; 48];

    /*
     * Attribute type being indexed.
     *
     * 0x30 = FILE_NAME
     */
    index_root[0..4].copy_from_slice(&0x30u32.to_le_bytes());

    /*
     * Collation rule.
     */
    index_root[4..8].copy_from_slice(&0u32.to_le_bytes());

    /*
     * Index block size.
     */
    index_root[8..12].copy_from_slice(&4096u32.to_le_bytes());

    /*
     * Clusters per index block.
     */
    index_root[12..16].copy_from_slice(&1u32.to_le_bytes());

    /*
     * ---------------------------------------------------------
     * INDEX_HEADER
     * ---------------------------------------------------------
     *
     * INDEX_HEADER begins at offset 16.
     *
     * The first INDEX_ENTRY begins 16 bytes
     * after the INDEX_HEADER.
     *
     * Therefore:
     *
     * 16 + 16 = 32
     */
    index_root[16..20].copy_from_slice(&16u32.to_le_bytes());

    /*
     * Total size of INDEX_HEADER + entries.
     */
    index_root[20..24].copy_from_slice(&32u32.to_le_bytes());

    /*
     * Allocated size.
     */
    index_root[24..28].copy_from_slice(&32u32.to_le_bytes());

    /*
     * INDEX_HEADER flags.
     */
    index_root[28..32].copy_from_slice(&0u32.to_le_bytes());

    /*
     * ---------------------------------------------------------
     * INDEX_ENTRY
     * ---------------------------------------------------------
     */

    let entry = 32usize;

    /*
     * MFT file reference.
     *
     * This entry points to MFT record 5.
     */
    index_root[entry..entry + 8].copy_from_slice(&5u64.to_le_bytes());

    /*
     * Total INDEX_ENTRY length.
     */
    index_root[entry + 8..entry + 10].copy_from_slice(&16u16.to_le_bytes());

    /*
     * Key length.
     *
     * The current test is intentionally testing
     * the INDEX_ROOT structure, not FILE_NAME parsing.
     */
    index_root[entry + 10..entry + 12].copy_from_slice(&0u16.to_le_bytes());

    /*
     * INDEX_ENTRY flags.
     *
     * 0x0002 would mean the final/end entry.
     *
     * Therefore this normal entry remains
     * available to the parser.
     */
    index_root[entry + 12..entry + 14].copy_from_slice(&0u16.to_le_bytes());

    /*
     * ---------------------------------------------------------
     * NTFS ATTRIBUTE HEADER
     * ---------------------------------------------------------
     *
     * Attribute starts at offset 56.
     *
     * Type:
     *
     * 0x90 = INDEX_ROOT
     *
     * Resident attribute:
     *
     * common header = 16 bytes
     * resident header/value metadata = 6 bytes
     * value = INDEX_ROOT
     */

    let attribute_offset = 56usize;

    let value_offset = 22usize;

    let attribute_length = value_offset + index_root.len();

    /*
     * Attribute type:
     *
     * 0x90 = INDEX_ROOT
     */
    data[attribute_offset..attribute_offset + 4].copy_from_slice(&0x90u32.to_le_bytes());

    /*
     * Complete attribute length.
     */
    data[attribute_offset + 4..attribute_offset + 8]
        .copy_from_slice(&(attribute_length as u32).to_le_bytes());

    /*
     * Resident flag.
     *
     * 0 = resident
     */
    data[attribute_offset + 8] = 0;

    /*
     * Name length.
     */
    data[attribute_offset + 9] = 0;

    /*
     * Name offset.
     */
    data[attribute_offset + 10..attribute_offset + 12].copy_from_slice(&0u16.to_le_bytes());

    /*
     * Attribute flags.
     */
    data[attribute_offset + 12..attribute_offset + 14].copy_from_slice(&0u16.to_le_bytes());

    /*
     * Attribute ID.
     */
    data[attribute_offset + 14..attribute_offset + 16].copy_from_slice(&0u16.to_le_bytes());

    /*
     * Resident value length.
     */
    data[attribute_offset + 16..attribute_offset + 20]
        .copy_from_slice(&(index_root.len() as u32).to_le_bytes());

    /*
     * Resident value offset.
     *
     * Relative to the beginning of the
     * NTFS attribute.
     */
    data[attribute_offset + 20..attribute_offset + 22]
        .copy_from_slice(&(value_offset as u16).to_le_bytes());

    /*
     * Copy the INDEX_ROOT value into
     * the resident attribute.
     */
    data[attribute_offset + value_offset..attribute_offset + value_offset + index_root.len()]
        .copy_from_slice(&index_root);

    /*
     * ---------------------------------------------------------
     * END ATTRIBUTE
     * ---------------------------------------------------------
     *
     * NTFS marks the end of the attribute
     * list with:
     *
     * 0xFFFFFFFF
     */

    let end_offset = attribute_offset + attribute_length;

    data[end_offset..end_offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    /*
     * ---------------------------------------------------------
     * CREATE MFT RECORD
     * ---------------------------------------------------------
     */

    MftRecord::new(5, data).expect("MFT record should be valid")
}

#[test]
fn test_mft_parser_reads_index_root() {
    let mut record = create_mft_record_with_index_root();

    let parsed = MftParser::parse(&mut record).expect("MFT record with INDEX_ROOT should parse");

    let index_root = parsed
        .index_root
        .expect("Parsed MFT record should contain INDEX_ROOT");

    assert_eq!(index_root.indexed_attribute_type, 0x30);

    assert_eq!(index_root.collation_rule, 0);

    assert_eq!(index_root.index_block_size, 4096);

    assert_eq!(index_root.entries.len(), 1);

    assert_eq!(index_root.entries[0].file_reference, 5);
}

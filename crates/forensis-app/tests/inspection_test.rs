use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use forensis_app::inspect_image;
use forensis_core::PartitionTableType;

#[test]
fn test_inspect_image_detects_mbr() {
    let temp_dir = tempfile::tempdir().unwrap();

    let image_path = temp_dir.path().join("test.img");

    let mut file = File::create(&image_path).unwrap();

    let mut mbr = [0u8; 512];

    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    mbr[446] = 0x00;
    mbr[450] = 0x07;

    mbr[454..458].copy_from_slice(&2048u32.to_le_bytes());

    mbr[458..462].copy_from_slice(&4096u32.to_le_bytes());

    file.write_all(&mbr).unwrap();

    file.seek(SeekFrom::Start(512 + 4096 * 512 - 1)).unwrap();

    file.write_all(&[0u8]).unwrap();

    drop(file);

    let result = inspect_image(&image_path).unwrap();

    assert_eq!(result.partition_table, Some(PartitionTableType::Mbr));

    assert_eq!(result.partitions.len(), 1);

    let partition = &result.partitions[0];

    assert_eq!(partition.number, 1);

    assert_eq!(partition.start_sector, 2048);

    assert_eq!(partition.sector_count, 4096);
}

#[test]
fn test_inspect_image_detects_gpt() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    /*
     * ---------------------------------------------------------
     * GPT layout
     *
     * LBA 0:
     *   Protective MBR
     *
     * LBA 1:
     *   GPT header
     *
     * LBA 2-33:
     *   GPT partition-entry array
     *
     * LBA 34:
     *   First usable sector
     *
     * We create a small but structurally valid GPT image.
     * ---------------------------------------------------------
     */

    let mut file = NamedTempFile::new().expect("failed to create temporary image");

    let sector_size = 512usize;

    let total_sectors = 40usize;

    let mut data = vec![0u8; sector_size * total_sectors];

    /*
     * ---------------------------------------------------------
     * Protective MBR
     * ---------------------------------------------------------
     */

    let mbr_offset = 0usize;

    data[mbr_offset + 446] = 0x00;

    /*
     * Partition type 0xEE means GPT protective MBR.
     */
    data[mbr_offset + 450] = 0xEE;

    /*
     * Protective partition starts at LBA 1.
     */
    data[mbr_offset + 454..458].copy_from_slice(&1u32.to_le_bytes());

    /*
     * Number of sectors.
     */
    let protective_size = (total_sectors - 1) as u32;

    data[mbr_offset + 458..462].copy_from_slice(&protective_size.to_le_bytes());

    /*
     * MBR signature.
     */
    data[mbr_offset + 510] = 0x55;

    data[mbr_offset + 511] = 0xAA;

    /*
     * ---------------------------------------------------------
     * GPT header at LBA 1.
     * ---------------------------------------------------------
     */

    let header_offset = sector_size;

    /*
     * Signature.
     */
    data[header_offset..header_offset + 8].copy_from_slice(b"EFI PART");

    /*
     * GPT revision 1.0.
     *
     * Offset 8.
     */
    data[header_offset + 8..header_offset + 12].copy_from_slice(&0x00010000u32.to_le_bytes());

    /*
     * Header size = 92 bytes.
     *
     * Offset 12.
     */
    data[header_offset + 12..header_offset + 16].copy_from_slice(&92u32.to_le_bytes());

    /*
     * Current LBA = 1.
     *
     * Offset 24.
     */
    data[header_offset + 24..header_offset + 32].copy_from_slice(&1u64.to_le_bytes());

    /*
     * Backup LBA = 39.
     *
     * Offset 32.
     */
    data[header_offset + 32..header_offset + 40].copy_from_slice(&39u64.to_le_bytes());

    /*
     * First usable LBA = 34.
     *
     * Offset 40.
     */
    data[header_offset + 40..header_offset + 48].copy_from_slice(&34u64.to_le_bytes());

    /*
     * Last usable LBA = 38.
     *
     * Offset 48.
     */
    data[header_offset + 48..header_offset + 56].copy_from_slice(&38u64.to_le_bytes());

    /*
     * Disk GUID.
     *
     * Offset 56.
     */
    data[header_offset + 56..header_offset + 72].copy_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ]);

    /*
     * Partition-entry array starts at LBA 2.
     *
     * Offset 72.
     */
    let partition_entry_lba = 2u64;

    data[header_offset + 72..header_offset + 80]
        .copy_from_slice(&partition_entry_lba.to_le_bytes());

    /*
     * Number of entries = 4.
     *
     * Offset 80.
     */
    let number_of_entries = 4u32;

    data[header_offset + 80..header_offset + 84].copy_from_slice(&number_of_entries.to_le_bytes());

    /*
     * Each GPT entry = 128 bytes.
     *
     * Offset 84.
     */
    let entry_size = 128u32;

    data[header_offset + 84..header_offset + 88].copy_from_slice(&entry_size.to_le_bytes());

    /*
     * We deliberately leave the CRC fields zero.
     *
     * The current Forensis GPT parser does not validate
     * the CRC yet.
     */

    /*
     * ---------------------------------------------------------
     * GPT partition-entry array.
     *
     * Four entries × 128 bytes = 512 bytes.
     *
     * All entries are empty.
     * ---------------------------------------------------------
     */

    let table_offset = partition_entry_lba as usize * sector_size;

    let table_size = number_of_entries as usize * entry_size as usize;

    assert_eq!(table_offset + table_size, 3 * sector_size);

    /*
     * The array is already zero-filled.
     */

    file.write_all(&data)
        .expect("failed to write GPT test image");

    /*
     * ---------------------------------------------------------
     * Run inspection.
     * ---------------------------------------------------------
     */

    let result = inspect_image(file.path()).expect("inspection failed");

    assert_eq!(result.partition_table, Some(PartitionTableType::Gpt));

    /*
     * The GPT table is valid but contains
     * no actual partitions.
     */
    assert!(result.partitions.is_empty());
}

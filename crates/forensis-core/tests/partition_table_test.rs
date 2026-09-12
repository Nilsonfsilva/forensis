use std::io::{Seek, SeekFrom, Write};

use forensis_core::{PartitionTableDetector, PartitionTableReader, PartitionTableType};

use forensis_core::disk::ImageReader;

#[test]
fn test_partition_table_detector_detects_mbr() {
    let temp_dir = tempfile::tempdir().unwrap();

    let image_path = temp_dir.path().join("mbr.img");

    let mut file = std::fs::File::create(&image_path).unwrap();

    let mut mbr = [0u8; 512];

    /*
     * MBR boot signature.
     */
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    /*
     * First partition entry.
     *
     * Offset 446:
     *   +4  partition type
     *   +8  starting LBA
     *   +12 sector count
     */
    mbr[446 + 4] = 0x07;

    mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());

    mbr[446 + 12..446 + 16].copy_from_slice(&4096u32.to_le_bytes());

    file.write_all(&mbr).unwrap();

    /*
     * Make the image physically large
     * enough to contain the partition.
     */
    let image_size = (2048u64 + 4096) * 512;

    file.seek(SeekFrom::Start(image_size - 1)).unwrap();

    file.write_all(&[0u8]).unwrap();

    drop(file);

    let mut reader = ImageReader::open(image_path.to_str().unwrap()).unwrap();

    let table = PartitionTableDetector::parse(&mut reader)
        .unwrap()
        .expect("MBR partition table should be detected");

    assert_eq!(table.table_type(), PartitionTableType::Mbr);

    let partitions = table.partitions();

    assert_eq!(partitions.len(), 1);

    assert_eq!(partitions[0].start_sector, 2048);

    assert_eq!(partitions[0].sector_count, 4096);
}

#[test]
fn test_partition_table_detector_detects_gpt() {
    let temp_dir = tempfile::tempdir().unwrap();

    let image_path = temp_dir.path().join("gpt.img");

    let mut file = std::fs::File::create(&image_path).unwrap();

    /*
     * ---------------------------------------------------------
     * GPT layout used by this test
     * ---------------------------------------------------------
     *
     * LBA 0:
     *     Protective MBR
     *
     * LBA 1:
     *     GPT header
     *
     * LBA 2:
     *     First GPT partition entry
     */

    let mut protective_mbr = [0u8; 512];

    /*
     * Protective MBR signature.
     */
    protective_mbr[510] = 0x55;
    protective_mbr[511] = 0xAA;

    /*
     * Protective MBR partition.
     *
     * Type 0xEE means GPT protective partition.
     */
    protective_mbr[446 + 4] = 0xEE;

    protective_mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());

    protective_mbr[446 + 12..446 + 16].copy_from_slice(&10000u32.to_le_bytes());

    file.write_all(&protective_mbr).unwrap();

    /*
     * ---------------------------------------------------------
     * GPT header — LBA 1
     * ---------------------------------------------------------
     */

    let mut header = [0u8; 512];

    /*
     * GPT signature.
     */
    header[0..8].copy_from_slice(b"EFI PART");

    /*
     * Revision 1.0.
     */
    header[8..12].copy_from_slice(&0x00010000u32.to_le_bytes());

    /*
     * Header size = 92 bytes.
     */
    header[12..16].copy_from_slice(&92u32.to_le_bytes());

    /*
     * Current LBA = 1.
     */
    header[24..32].copy_from_slice(&1u64.to_le_bytes());

    /*
     * Backup LBA.
     */
    header[32..40].copy_from_slice(&10000u64.to_le_bytes());

    /*
     * First usable LBA.
     */
    header[40..48].copy_from_slice(&34u64.to_le_bytes());

    /*
     * Last usable LBA.
     */
    header[48..56].copy_from_slice(&9967u64.to_le_bytes());

    /*
     * Partition entry array:
     *
     * LBA 2.
     */
    header[72..80].copy_from_slice(&2u64.to_le_bytes());

    /*
     * One partition entry.
     */
    header[80..84].copy_from_slice(&1u32.to_le_bytes());

    /*
     * Standard GPT entry size.
     */
    header[84..88].copy_from_slice(&128u32.to_le_bytes());

    file.write_all(&header).unwrap();

    /*
     * ---------------------------------------------------------
     * GPT partition entry — LBA 2
     * ---------------------------------------------------------
     */

    let mut entry = [0u8; 512];

    /*
     * Microsoft Basic Data partition GUID.
     */
    entry[0..16].copy_from_slice(&[
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ]);

    /*
     * Unique partition GUID.
     */
    entry[16..32].copy_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ]);

    /*
     * First LBA.
     */
    entry[32..40].copy_from_slice(&2048u64.to_le_bytes());

    /*
     * Last LBA.
     */
    entry[40..48].copy_from_slice(&4095u64.to_le_bytes());

    /*
     * Partition attributes.
     */
    entry[48..56].copy_from_slice(&0u64.to_le_bytes());

    /*
     * Partition name.
     *
     * UTF-16LE: "Forensis"
     */
    let name = "Forensis".encode_utf16().collect::<Vec<u16>>();

    for (index, character) in name.iter().enumerate() {
        let offset = 56 + index * 2;

        entry[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }

    file.write_all(&entry).unwrap();

    /*
     * Make the image physically large
     * enough for the declared GPT data.
     */
    let image_size = 10001u64 * 512;

    file.seek(SeekFrom::Start(image_size - 1)).unwrap();

    file.write_all(&[0u8]).unwrap();

    drop(file);

    /*
     * ---------------------------------------------------------
     * Run Forensis GPT parser.
     * ---------------------------------------------------------
     */

    let mut reader = ImageReader::open(image_path.to_str().unwrap()).unwrap();

    let table = PartitionTableDetector::parse(&mut reader)
        .unwrap()
        .expect("GPT partition table should be detected");

    assert_eq!(table.table_type(), PartitionTableType::Gpt);

    let partitions = table.partitions();

    assert_eq!(partitions.len(), 1);

    assert_eq!(partitions[0].number, 1);

    assert_eq!(partitions[0].start_sector, 2048);

    assert_eq!(partitions[0].sector_count, 2048);
}

#[test]
fn test_partition_table_detector_returns_none_for_unknown() {
    let temp_dir = tempfile::tempdir().unwrap();

    let image_path = temp_dir.path().join("unknown.img");

    let mut file = std::fs::File::create(&image_path).unwrap();

    /*
     * The detector reads:
     *
     *   LBA 0 -> MBR
     *   LBA 1 -> GPT header
     *
     * Therefore the test image must contain
     * at least two sectors.
     */
    let image = [0u8; 1024];

    file.write_all(&image).unwrap();

    drop(file);

    let mut reader = ImageReader::open(image_path.to_str().unwrap()).unwrap();

    let result = PartitionTableDetector::parse(&mut reader).unwrap();

    assert!(result.is_none());
}

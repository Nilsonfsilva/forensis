use forensis_core::{ImageReader, Mbr, PartitionType};

use std::fs::File;
use std::io::Write;

#[test]
fn test_mbr_partition_detection() {
    let path = "test_mbr.img";

    let mut sector = [0u8; 512];

    sector[446 + 4] = 0x07;

    sector[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());

    sector[446 + 12..446 + 16].copy_from_slice(&409600u32.to_le_bytes());

    sector[510] = 0x55;
    sector[511] = 0xAA;

    let mut file = File::create(path).unwrap();

    file.write_all(&sector).unwrap();

    drop(file);

    let mut reader = ImageReader::open(path).unwrap();

    let mbr = Mbr::parse(&mut reader).unwrap();

    assert_eq!(mbr.partitions.len(), 1);

    assert_eq!(mbr.partitions[0].partition_type, PartitionType::Ntfs);

    assert_eq!(mbr.partitions[0].start_sector, 2048);

    assert_eq!(mbr.partitions[0].sector_count, 409600);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn test_mbr_linux_partition() {
    let path = "test_mbr_linux.img";

    let mut sector = [0u8; 512];

    // Partition type: Linux filesystem
    sector[446 + 4] = 0x83;

    // First LBA
    sector[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());

    // Number of sectors
    sector[446 + 12..446 + 16].copy_from_slice(&18432u32.to_le_bytes());

    // MBR signature
    sector[510] = 0x55;
    sector[511] = 0xAA;

    let mut file = File::create(path).unwrap();

    file.write_all(&sector).unwrap();

    drop(file);

    let mut reader = ImageReader::open(path).unwrap();

    let mbr = Mbr::parse(&mut reader).unwrap();

    assert_eq!(mbr.partitions.len(), 1);

    assert_eq!(
        mbr.partitions[0].partition_type,
        PartitionType::LinuxFilesystem
    );

    assert_eq!(mbr.partitions[0].start_sector, 2048);

    assert_eq!(mbr.partitions[0].sector_count, 18432);

    std::fs::remove_file(path).unwrap();
}

use forensis_core::error::ForensisError;
use forensis_core::filesystem::ext4::{
    Ext4BlockGroupDescriptor, Ext4BlockGroupTable, Ext4Filesystem, Ext4Inode, Ext4Reader,
    Ext4Superblock,
};
use forensis_core::result::Result;
use forensis_core::traits::Readable;
use forensis_core::types::{ByteOffset, ByteSize};

struct MemoryReader {
    data: Vec<u8>,
}

impl MemoryReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl Readable for MemoryReader {
    fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
        let start = offset.value() as usize;
        let end = start
            .checked_add(buffer.len())
            .ok_or_else(|| ForensisError::InvalidFormat("Read offset overflow".to_string()))?;

        if end > self.data.len() {
            return Err(ForensisError::InvalidFormat(
                "Read exceeds memory reader bounds".to_string(),
            ));
        }

        buffer.copy_from_slice(&self.data[start..end]);

        Ok(())
    }

    fn size(&self) -> ByteSize {
        ByteSize::new(self.data.len() as u64)
    }
}

fn build_superblock() -> Vec<u8> {
    let mut data = vec![0u8; Ext4Superblock::SIZE];

    data[0x00..0x04].copy_from_slice(&100u32.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&1000u32.to_le_bytes());
    data[0x0C..0x10].copy_from_slice(&200u32.to_le_bytes());
    data[0x10..0x14].copy_from_slice(&20u32.to_le_bytes());
    data[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    data[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
    data[0x20..0x24].copy_from_slice(&100u32.to_le_bytes());
    data[0x28..0x2C].copy_from_slice(&10u32.to_le_bytes());
    data[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    data[0x58..0x5A].copy_from_slice(&128u16.to_le_bytes());

    data
}

fn build_descriptor(
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
) -> Ext4BlockGroupDescriptor {
    let mut data = vec![0u8; Ext4BlockGroupDescriptor::SIZE];

    data[0x00..0x04].copy_from_slice(&block_bitmap.to_le_bytes());
    data[0x04..0x08].copy_from_slice(&inode_bitmap.to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&inode_table.to_le_bytes());
    data[0x0C..0x0E].copy_from_slice(&10u16.to_le_bytes());
    data[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
    data[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());

    Ext4BlockGroupDescriptor::parse(&data).expect("descriptor should parse")
}

fn build_table() -> Ext4BlockGroupTable {
    let descriptor = build_descriptor(10, 11, 12);

    let mut data = vec![0u8; Ext4BlockGroupDescriptor::SIZE * 2];

    let descriptor_data = {
        let mut bytes = vec![0u8; Ext4BlockGroupDescriptor::SIZE];

        bytes[0x00..0x04].copy_from_slice(&(descriptor.block_bitmap() as u32).to_le_bytes());
        bytes[0x04..0x08].copy_from_slice(&(descriptor.inode_bitmap() as u32).to_le_bytes());
        bytes[0x08..0x0C].copy_from_slice(&(descriptor.inode_table() as u32).to_le_bytes());
        bytes[0x0C..0x0E].copy_from_slice(&10u16.to_le_bytes());
        bytes[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());

        bytes
    };

    data[0..Ext4BlockGroupDescriptor::SIZE].copy_from_slice(&descriptor_data);
    data[Ext4BlockGroupDescriptor::SIZE..Ext4BlockGroupDescriptor::SIZE * 2]
        .copy_from_slice(&descriptor_data);

    Ext4BlockGroupTable::parse(&data).expect("table should parse")
}

fn build_integration_image() -> MemoryReader {
    let block_size = 4096usize;
    let image_size = 65536usize;

    let mut image = vec![0u8; image_size];

    // Superblock.
    let superblock_offset = 1024usize;

    image[superblock_offset..superblock_offset + 4].copy_from_slice(&16u32.to_le_bytes());
    image[superblock_offset + 4..superblock_offset + 8].copy_from_slice(&16u32.to_le_bytes());
    image[superblock_offset + 0x0C..superblock_offset + 0x10].copy_from_slice(&8u32.to_le_bytes());
    image[superblock_offset + 0x10..superblock_offset + 0x14].copy_from_slice(&8u32.to_le_bytes());
    image[superblock_offset + 0x14..superblock_offset + 0x18].copy_from_slice(&0u32.to_le_bytes());
    image[superblock_offset + 0x18..superblock_offset + 0x1C].copy_from_slice(&2u32.to_le_bytes());
    image[superblock_offset + 0x20..superblock_offset + 0x24].copy_from_slice(&8u32.to_le_bytes());
    image[superblock_offset + 0x28..superblock_offset + 0x2C].copy_from_slice(&8u32.to_le_bytes());
    image[superblock_offset + 0x38..superblock_offset + 0x3A]
        .copy_from_slice(&0xEF53u16.to_le_bytes());
    image[superblock_offset + 0x58..superblock_offset + 0x5A]
        .copy_from_slice(&128u16.to_le_bytes());

    // Block group descriptor table at block 1.
    let descriptor_offset = block_size;

    // Group 0.
    image[descriptor_offset..descriptor_offset + 4].copy_from_slice(&10u32.to_le_bytes());
    image[descriptor_offset + 4..descriptor_offset + 8].copy_from_slice(&11u32.to_le_bytes());
    image[descriptor_offset + 8..descriptor_offset + 12].copy_from_slice(&12u32.to_le_bytes());
    image[descriptor_offset + 12..descriptor_offset + 14].copy_from_slice(&4u16.to_le_bytes());
    image[descriptor_offset + 14..descriptor_offset + 16].copy_from_slice(&4u16.to_le_bytes());
    image[descriptor_offset + 16..descriptor_offset + 18].copy_from_slice(&1u16.to_le_bytes());

    // Group 1.
    let group1_offset = descriptor_offset + Ext4BlockGroupDescriptor::SIZE;

    image[group1_offset..group1_offset + 4].copy_from_slice(&13u32.to_le_bytes());
    image[group1_offset + 4..group1_offset + 8].copy_from_slice(&14u32.to_le_bytes());
    image[group1_offset + 8..group1_offset + 12].copy_from_slice(&15u32.to_le_bytes());
    image[group1_offset + 12..group1_offset + 14].copy_from_slice(&4u16.to_le_bytes());
    image[group1_offset + 14..group1_offset + 16].copy_from_slice(&4u16.to_le_bytes());
    image[group1_offset + 16..group1_offset + 18].copy_from_slice(&1u16.to_le_bytes());

    // Block bitmap for group 0.
    image[10 * block_size] = 0b0000_1111;

    // Inode bitmap for group 0.
    image[11 * block_size] = 0b0000_1111;

    // Inode bitmap for group 1.
    image[14 * block_size] = 0b0000_1111;

    // Inode 1: regular file.
    let inode1_offset = 12 * block_size;

    image[inode1_offset..inode1_offset + 2].copy_from_slice(&0x8000u16.to_le_bytes());

    // Inode 2: directory.
    let inode2_offset = inode1_offset + 128;

    image[inode2_offset..inode2_offset + 2].copy_from_slice(&0x4000u16.to_le_bytes());

    MemoryReader::new(image)
}

#[test]
fn creates_filesystem_with_valid_metadata() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.superblock().magic(), 0xEF53);
    assert_eq!(filesystem.superblock().inodes_count(), 100);
    assert_eq!(filesystem.superblock().blocks_count(), 1000);
    assert_eq!(filesystem.superblock().inode_size(), 128);
}

#[test]
fn accepts_single_block_group_table() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let descriptor = build_descriptor(10, 11, 12);

    let mut data = vec![0u8; Ext4BlockGroupDescriptor::SIZE];

    data[0x00..0x04].copy_from_slice(&(descriptor.block_bitmap() as u32).to_le_bytes());
    data[0x04..0x08].copy_from_slice(&(descriptor.inode_bitmap() as u32).to_le_bytes());
    data[0x08..0x0C].copy_from_slice(&(descriptor.inode_table() as u32).to_le_bytes());
    data[0x0C..0x0E].copy_from_slice(&10u16.to_le_bytes());
    data[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
    data[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());

    let table = Ext4BlockGroupTable::parse(&data).expect("table should parse");

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.block_group_count(), 1);
}

#[test]
fn exposes_superblock() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    let exposed = filesystem.superblock();

    assert_eq!(exposed.magic(), 0xEF53);
    assert_eq!(exposed.inodes_count(), 100);
    assert_eq!(exposed.blocks_count(), 1000);
    assert_eq!(exposed.free_blocks_count(), 200);
    assert_eq!(exposed.free_inodes_count(), 20);
    assert_eq!(exposed.first_data_block(), 1);
    assert_eq!(exposed.block_size(), 4096);
    assert_eq!(exposed.blocks_per_group(), 100);
    assert_eq!(exposed.inodes_per_group(), 10);
    assert_eq!(exposed.inode_size(), 128);
}

#[test]
fn exposes_block_groups() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    let exposed = filesystem.block_groups();

    assert_eq!(exposed.len(), 2);

    let first = exposed.get(0).expect("first block group should exist");

    assert_eq!(first.block_bitmap(), 10);
    assert_eq!(first.inode_bitmap(), 11);
    assert_eq!(first.inode_table(), 12);
}

#[test]
fn returns_valid_block_group() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    let group = filesystem.block_group(0).expect("block group should exist");

    assert_eq!(group.block_bitmap(), 10);
    assert_eq!(group.inode_bitmap(), 11);
    assert_eq!(group.inode_table(), 12);
}

#[test]
fn rejects_invalid_block_group_index() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert!(filesystem.block_group(100).is_none());
}

#[test]
fn exposes_block_size() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.block_size(), 4096);
}

#[test]
fn exposes_inode_count() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.inode_count(), 100);
}

#[test]
fn exposes_block_count() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.block_count(), 1000);
}

#[test]
fn exposes_free_block_count() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.free_block_count(), 200);
}

#[test]
fn exposes_free_inode_count() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.free_inode_count(), 20);
}

#[test]
fn exposes_block_group_count() {
    let superblock = Ext4Superblock::parse(&build_superblock()).expect("superblock should parse");

    let table = build_table();

    let filesystem = Ext4Filesystem::new(superblock, table).expect("filesystem should be created");

    assert_eq!(filesystem.block_group_count(), 2);
}

#[test]
fn opens_filesystem_from_reader() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    assert_eq!(filesystem.block_size(), 4096);
    assert_eq!(filesystem.inode_count(), 16);
    assert_eq!(filesystem.block_count(), 16);
    assert_eq!(filesystem.block_group_count(), 2);
}

#[test]
fn reads_block_bitmap_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    let bitmap = filesystem
        .read_block_bitmap(&mut ext4_reader, 0)
        .expect("block bitmap should be readable");

    assert!(bitmap.is_allocated(0));
    assert!(bitmap.is_allocated(1));
    assert!(bitmap.is_allocated(2));
    assert!(bitmap.is_allocated(3));
    assert!(!bitmap.is_allocated(4));
}

#[test]
fn reads_inode_bitmap_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    let bitmap = filesystem
        .read_inode_bitmap(&mut ext4_reader, 0)
        .expect("inode bitmap should be readable");

    assert!(bitmap.is_allocated(1));
    assert!(bitmap.is_allocated(2));
    assert!(bitmap.is_allocated(3));
    assert!(bitmap.is_allocated(4));
    assert!(!bitmap.is_allocated(5));
}

#[test]
fn reads_inode_table_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    let table = filesystem
        .read_inode_table(&mut ext4_reader, 0)
        .expect("inode table should be readable");

    assert_eq!(table.inode_size(), 128);
    assert_eq!(table.inode_count(), 32);

    let inode_one =
        Ext4Inode::parse(table.inode(0).expect("inode should exist")).expect("inode should parse");

    assert!(inode_one.is_regular_file());

    let inode_two =
        Ext4Inode::parse(table.inode(1).expect("inode should exist")).expect("inode should parse");

    assert!(inode_two.is_directory());
}

#[test]
fn reads_inode_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    let inode = filesystem
        .read_inode(&mut ext4_reader, 1)
        .expect("inode 1 should be readable");

    assert!(inode.is_regular_file());
    assert!(!inode.is_directory());
}

#[test]
fn reads_directory_inode_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    let inode = filesystem
        .read_inode(&mut ext4_reader, 2)
        .expect("inode 2 should be readable");

    assert!(inode.is_directory());
    assert!(!inode.is_regular_file());
}

#[test]
fn rejects_zero_inode_number_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    assert!(filesystem.read_inode(&mut ext4_reader, 0).is_err());
}

#[test]
fn rejects_inode_number_outside_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    assert!(filesystem.read_inode(&mut ext4_reader, 17).is_err());
}

#[test]
fn reads_complete_block_group_through_filesystem() {
    let reader = build_integration_image();
    let mut ext4_reader = Ext4Reader::new(reader, 0);

    let filesystem = Ext4Filesystem::open(&mut ext4_reader).expect("filesystem should open");

    let (block_bitmap, inode_bitmap, inode_table) = filesystem
        .read_block_group(&mut ext4_reader, 0)
        .expect("block group should be readable");

    assert!(block_bitmap.is_allocated(0));
    assert!(inode_bitmap.is_allocated(1));
    assert_eq!(inode_table.inode_size(), 128);
    assert_eq!(inode_table.inode_count(), 32);
}

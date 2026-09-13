use forensis_core::error::ForensisError;
use forensis_core::filesystem::ext4::Ext4Reader;
use forensis_core::result::Result;
use forensis_core::traits::Readable;
use forensis_core::types::{ByteOffset, ByteSize};

struct MemoryReader {
    data: Vec<u8>,
}

impl MemoryReader {
    fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }
}

impl Readable for MemoryReader {
    fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.value()).map_err(|_| {
            ForensisError::InvalidFormat("Memory reader offset is too large".to_string())
        })?;

        let end = start.checked_add(buffer.len()).ok_or_else(|| {
            ForensisError::InvalidFormat("Memory reader offset overflow".to_string())
        })?;

        if end > self.data.len() {
            return Err(ForensisError::InvalidFormat(
                "Memory reader read exceeds available data".to_string(),
            ));
        }

        buffer.copy_from_slice(&self.data[start..end]);

        Ok(())
    }

    fn size(&self) -> ByteSize {
        ByteSize::new(self.data.len() as u64)
    }
}

#[allow(clippy::identity_op)]
fn write_superblock(data: &mut [u8], partition_offset: usize) {
    let offset = partition_offset + 1024;

    data[offset + 0x00..offset + 0x04].copy_from_slice(&16384u32.to_le_bytes());
    data[offset + 0x04..offset + 0x08].copy_from_slice(&16384u32.to_le_bytes());
    data[offset + 0x0C..offset + 0x10].copy_from_slice(&8000u32.to_le_bytes());
    data[offset + 0x10..offset + 0x14].copy_from_slice(&16000u32.to_le_bytes());
    data[offset + 0x14..offset + 0x18].copy_from_slice(&0u32.to_le_bytes());
    data[offset + 0x18..offset + 0x1C].copy_from_slice(&2u32.to_le_bytes());
    data[offset + 0x20..offset + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    data[offset + 0x28..offset + 0x2C].copy_from_slice(&8192u32.to_le_bytes());
    data[offset + 0x38..offset + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    data[offset + 0x58..offset + 0x5A].copy_from_slice(&256u16.to_le_bytes());
}

#[allow(clippy::identity_op)]
fn write_block_group_table(data: &mut [u8], partition_offset: usize) {
    let table_offset = partition_offset + 4096;

    let descriptor0 = [100u32, 200u32, 300u32];

    data[table_offset + 0x00..table_offset + 0x04].copy_from_slice(&descriptor0[0].to_le_bytes());

    data[table_offset + 0x04..table_offset + 0x08].copy_from_slice(&descriptor0[1].to_le_bytes());

    data[table_offset + 0x08..table_offset + 0x0C].copy_from_slice(&descriptor0[2].to_le_bytes());

    data[table_offset + 0x0C..table_offset + 0x0E].copy_from_slice(&400u16.to_le_bytes());

    data[table_offset + 0x0E..table_offset + 0x10].copy_from_slice(&500u16.to_le_bytes());

    data[table_offset + 0x10..table_offset + 0x12].copy_from_slice(&600u16.to_le_bytes());

    let descriptor1_offset = table_offset + 32;

    data[descriptor1_offset + 0x00..descriptor1_offset + 0x04]
        .copy_from_slice(&1000u32.to_le_bytes());

    data[descriptor1_offset + 0x04..descriptor1_offset + 0x08]
        .copy_from_slice(&2000u32.to_le_bytes());

    data[descriptor1_offset + 0x08..descriptor1_offset + 0x0C]
        .copy_from_slice(&3000u32.to_le_bytes());

    data[descriptor1_offset + 0x0C..descriptor1_offset + 0x0E]
        .copy_from_slice(&4000u16.to_le_bytes());

    data[descriptor1_offset + 0x0E..descriptor1_offset + 0x10]
        .copy_from_slice(&5000u16.to_le_bytes());

    data[descriptor1_offset + 0x10..descriptor1_offset + 0x12]
        .copy_from_slice(&6000u16.to_le_bytes());
}

#[test]
fn reads_superblock_at_partition_offset() {
    let partition_offset = 2048usize;

    let mut reader = MemoryReader::new(16384);

    write_superblock(&mut reader.data, partition_offset);

    let mut ext4_reader = Ext4Reader::new(reader, partition_offset as u64);

    let superblock = ext4_reader
        .read_superblock()
        .expect("EXT4 superblock should be readable");

    assert_eq!(ext4_reader.partition_offset(), partition_offset as u64);
    assert_eq!(superblock.magic(), 0xEF53);
    assert_eq!(superblock.block_size(), 4096);
    assert_eq!(superblock.blocks_count(), 16384);
    assert_eq!(superblock.blocks_per_group(), 8192);
    assert_eq!(superblock.inodes_per_group(), 8192);
    assert_eq!(superblock.inode_size(), 256);
}

#[test]
fn reads_block_group_table() {
    let partition_offset = 2048usize;

    let mut reader = MemoryReader::new(16384);

    write_superblock(&mut reader.data, partition_offset);
    write_block_group_table(&mut reader.data, partition_offset);

    let mut ext4_reader = Ext4Reader::new(reader, partition_offset as u64);

    let superblock = ext4_reader
        .read_superblock()
        .expect("EXT4 superblock should be readable");

    let table = ext4_reader
        .read_block_groups(&superblock)
        .expect("EXT4 block group table should be readable");

    assert_eq!(table.len(), 2);

    let first = table.get(0).expect("first descriptor should exist");
    let second = table.get(1).expect("second descriptor should exist");

    assert_eq!(first.block_bitmap(), 100);
    assert_eq!(first.inode_bitmap(), 200);
    assert_eq!(first.inode_table(), 300);

    assert_eq!(second.block_bitmap(), 1000);
    assert_eq!(second.inode_bitmap(), 2000);
    assert_eq!(second.inode_table(), 3000);
}

#[test]
fn reads_metadata() {
    let partition_offset = 2048usize;

    let mut reader = MemoryReader::new(16384);

    write_superblock(&mut reader.data, partition_offset);
    write_block_group_table(&mut reader.data, partition_offset);

    let mut ext4_reader = Ext4Reader::new(reader, partition_offset as u64);

    let (superblock, table) = ext4_reader
        .read_metadata()
        .expect("EXT4 metadata should be readable");

    assert_eq!(superblock.magic(), 0xEF53);
    assert_eq!(superblock.block_size(), 4096);
    assert_eq!(table.len(), 2);
}

#[test]
fn rejects_read_beyond_available_data() {
    let partition_offset = 20000u64;

    let reader = MemoryReader::new(16384);
    let mut ext4_reader = Ext4Reader::new(reader, partition_offset);

    let result = ext4_reader.read_superblock();

    assert!(result.is_err());
}

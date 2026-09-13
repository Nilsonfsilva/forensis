//! Random access reader for exFAT volumes.
//!
//! The reader wraps a [`Readable`] evidence source together with the
//! parsed boot sector. All numbers imported here are partition-relative:
//! the caller supplies the origin byte offset of the partition inside
//! the image, and the reader translates partition-relative offsets into
//! absolute ones before hitting the underlying source.

use crate::error::ForensisError;
use crate::filesystem::exfat::boot::ExFatBootSector;
use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

/// FAT entry value marking a bad cluster.
const FAT_BAD_CLUSTER: u32 = 0xFFFF_FFF7;

/// First FAT entry value that marks the end of a chain.
const FAT_END_OF_CHAIN: u32 = 0xFFFF_FFF8;

/// Maximum size of a directory cluster read request.
const MAX_DIRECTORY_BYTES: usize = 1 << 20;

/// Reads clusters, FAT entries and raw file data from an exFAT volume.
pub struct ExFatReader<R: Readable> {
    source: R,
    boot: ExFatBootSector,
    partition_offset: u64,
}

impl<R: Readable> ExFatReader<R> {
    /// Opens an exFAT volume located at `partition_offset` in the source.
    pub fn new(mut source: R, partition_offset: u64) -> Result<Self> {
        let mut boot_data = [0u8; 512];

        read_absolute(&mut source, partition_offset, &mut boot_data)?;

        let boot = ExFatBootSector::parse(&boot_data)?;

        Ok(Self {
            source,
            boot,
            partition_offset,
        })
    }

    /// Returns the parsed boot sector.
    pub fn boot(&self) -> &ExFatBootSector {
        &self.boot
    }

    /// Returns the cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.boot.cluster_size()
    }

    /// Returns the 512-based sectors per cluster.
    pub fn sectors_per_cluster(&self) -> u64 {
        self.boot.sectors_per_cluster_u64()
    }

    /// Reads a partition-relative range into `buffer`.
    pub fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let absolute = offset
            .checked_add(self.partition_offset)
            .ok_or_else(|| ForensisError::InvalidFormat("exFAT offset overflow".to_string()))?;

        self.source.read_at(ByteOffset::new(absolute), buffer)
    }

    /// Reads the partition-relative bytes covering a whole cluster chain.
    ///
    /// The first cluster is given by `start_cluster` and the chain is
    /// followed through the FAT until either `max_bytes` have been read
    /// or the end-of-chain mark is reached.
    pub fn read_chain(
        &mut self,
        start_cluster: u32,
        max_bytes: u64,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let cluster_size = self.cluster_size();

        let chain = self.walk_chain(start_cluster, max_bytes.div_ceil(cluster_size))?;

        let mut remaining = max_bytes;

        for cluster in chain {
            if remaining == 0 {
                break;
            }

            let chunk = remaining.min(cluster_size) as usize;

            let mut buffer = vec![0u8; chunk];

            self.read_cluster(cluster, &mut buffer)?;

            out.extend_from_slice(&buffer);

            remaining -= chunk as u64;
        }

        Ok(())
    }

    /// Walks the FAT chain starting at `start_cluster`.
    ///
    /// The returned vector contains the cluster numbers in order,
    /// stopping at the end-of-chain mark, after `max_clusters`
    /// entries, or when the FAT reports a loop.
    pub fn walk_chain(&mut self, start_cluster: u32, max_clusters: u64) -> Result<Vec<u32>> {
        if start_cluster == 0 {
            return Ok(Vec::new());
        }

        let mut chain = Vec::new();

        let mut seen = std::collections::HashSet::new();

        let mut cluster = start_cluster;

        loop {
            chain.push(cluster);

            if chain.len() as u64 >= max_clusters {
                break;
            }

            if !seen.insert(cluster) {
                break;
            }

            let entry = self.read_fat_entry(cluster)?;

            if entry >= FAT_END_OF_CHAIN || entry == FAT_BAD_CLUSTER || entry < 2 {
                break;
            }

            cluster = entry;
        }

        Ok(chain)
    }

    /// Reads the partition-relative bytes covering a single cluster.
    pub fn read_cluster(&mut self, cluster: u32, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() > self.cluster_size() as usize {
            return Err(ForensisError::InvalidFormat(
                "exFAT cluster read exceeds cluster size".to_string(),
            ));
        }

        let offset = self
            .boot
            .cluster_byte_offset(cluster)
            .ok_or_else(|| ForensisError::InvalidFormat("invalid cluster number".to_string()))?;

        self.read_at(offset, buffer)
    }

    /// Reads the regular directory entries stored in a cluster.
    ///
    /// Directories are usually smaller than a single cluster, so a
    /// full cluster sized buffer is returned with trailing zeros intact.
    pub fn read_directory_cluster(&mut self, cluster: u32) -> Result<Vec<u8>> {
        let cluster_size = self.cluster_size() as usize;

        if cluster_size > MAX_DIRECTORY_BYTES {
            return Err(ForensisError::InvalidFormat(
                "exFAT directory cluster too large".to_string(),
            ));
        }

        let mut buffer = vec![0u8; cluster_size];

        self.read_cluster(cluster, &mut buffer)?;

        Ok(buffer)
    }

    /// Reads a raw FAT entry (4 bytes) for the given cluster.
    pub fn read_fat_entry(&mut self, cluster: u32) -> Result<u32> {
        if cluster < 2 || cluster > self.boot.cluster_count() {
            return Err(ForensisError::InvalidFormat(
                "exFAT cluster out of range".to_string(),
            ));
        }

        let fat_offset = self.boot.fat_offset() as u64 * self.boot.bytes_per_sector() as u64;

        let entry_offset = fat_offset + cluster as u64 * 4;

        let mut raw = [0u8; 4];

        self.read_at(entry_offset, &mut raw)?;

        Ok(u32::from_le_bytes(raw))
    }

    /// Reads an arbitrary partition-relative sequence of bytes into a vector.
    pub fn read_bytes(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];

        self.read_at(offset, &mut buffer)?;

        Ok(buffer)
    }

    /// Consumes the reader and returns the wrapped source.
    pub fn into_inner(self) -> R {
        self.source
    }
}

fn read_absolute(source: &mut impl Readable, offset: u64, buffer: &mut [u8]) -> Result<()> {
    source.read_at(ByteOffset::new(offset), buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteOffset, ByteSize};

    struct MemorySource {
        data: Vec<u8>,
    }

    impl Readable for MemorySource {
        fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
            let offset = offset.value() as usize;

            if offset >= self.data.len() {
                buffer.fill(0);
                return Ok(());
            }

            let end = (offset + buffer.len()).min(self.data.len());

            buffer[..end - offset].copy_from_slice(&self.data[offset..end]);

            buffer[end - offset..].fill(0);

            Ok(())
        }

        fn size(&self) -> ByteSize {
            ByteSize::new(self.data.len() as u64)
        }
    }

    /// Builds a 64 MiB image: 512-byte sectors, 1 sector per cluster,
    /// FAT region at sector 128, two FATs of 1024 sectors each, so the
    /// cluster heap starts at sector 2176.
    fn image(partition_offset: u64) -> Vec<u8> {
        let img = vec![0u8; 64 * 1024 * 1024];

        let mut padded = vec![0u8; partition_offset as usize];
        padded.extend_from_slice(&img);
        padded.extend_from_slice(&[0u8; 512]);

        let mut boot = vec![0u8; 512];
        boot[0x03..0x0B].copy_from_slice(b"EXFAT   ");
        boot[0x40..0x48].copy_from_slice(&0u64.to_le_bytes());
        boot[0x48..0x50].copy_from_slice(&((64 * 1024 * 1024 / 512) as u64).to_le_bytes());
        boot[0x50..0x54].copy_from_slice(&128u32.to_le_bytes());
        boot[0x54..0x58].copy_from_slice(&1024u32.to_le_bytes());
        boot[0x58..0x5C].copy_from_slice(&(128u32 + 1024u32 * 2).to_le_bytes());
        boot[0x5C..0x60].copy_from_slice(&(122879u32).to_le_bytes());
        boot[0x60..0x64].copy_from_slice(&2u32.to_le_bytes());
        boot[0x6C] = 9;
        boot[0x6D] = 0;
        boot[0x6E] = 2;
        boot[0x1FE] = 0x55;
        boot[0x1FF] = 0xAA;

        padded[partition_offset as usize..partition_offset as usize + 512].copy_from_slice(&boot);

        padded
    }

    #[test]
    fn reads_boot_sector_at_partition_offset() {
        let img = image(1024 * 1024);
        let reader = ExFatReader::new(MemorySource { data: img }, 1024 * 1024).unwrap();

        assert_eq!(reader.cluster_size(), 512);
        assert_eq!(reader.boot().root_directory_cluster(), 2);
        assert_eq!(reader.sectors_per_cluster(), 1);
    }

    #[test]
    fn reads_fat_entry_and_walks_chain() {
        let mut img = image(0);

        // FAT region starts at sector 128. The first FAT entry of
        // cluster 3 is stored at byte 128*512 + 3*4. Set it to chain 3->4->EOC.
        let fat_base = 128 * 512usize;
        img[fat_base + 3 * 4..fat_base + 3 * 4 + 4].copy_from_slice(&4u32.to_le_bytes());
        img[fat_base + 4 * 4..fat_base + 4 * 4 + 4]
            .copy_from_slice(&(0xFFFF_FFF8u32).to_le_bytes());

        let mut reader = ExFatReader::new(MemorySource { data: img }, 0).unwrap();

        assert_eq!(reader.read_fat_entry(3).unwrap(), 4);
        assert_eq!(reader.read_fat_entry(4).unwrap(), 0xFFFF_FFF8);

        let chain = reader.walk_chain(3, 16).unwrap();
        assert_eq!(chain, vec![3, 4]);
    }

    #[test]
    fn stops_at_eof_mark() {
        let mut img = image(0);

        let fat_base = 128 * 512usize;
        img[fat_base + 3 * 4..fat_base + 3 * 4 + 4]
            .copy_from_slice(&(0xFFFF_FFFFu32).to_le_bytes());

        let mut reader = ExFatReader::new(MemorySource { data: img }, 0).unwrap();

        let chain = reader.walk_chain(3, 16).unwrap();
        assert_eq!(chain, vec![3]);
    }

    #[test]
    fn reads_cluster_at_computed_sector() {
        let mut img = image(0);

        // First data sector = 2176 (cluster 2). Cluster 3 data is at
        // sector 2177. Write a marker there.
        let sector = 2176 + 1;
        img[sector * 512..sector * 512 + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut reader = ExFatReader::new(MemorySource { data: img }, 0).unwrap();

        let mut buffer = [0u8; 4];
        reader.read_cluster(3, &mut buffer).unwrap();

        assert_eq!(buffer, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn read_chain_reassembles_data_across_clusters() {
        let mut img = image(0);

        let fat_base = 128 * 512usize;
        let first_data_sector = 2176u64;

        let chain = vec![5u32, 6, 7];
        let mut cur = 5u32;
        for next in chain.iter().skip(1).copied() {
            img[fat_base + cur as usize * 4..fat_base + cur as usize * 4 + 4]
                .copy_from_slice(&next.to_le_bytes());
            cur = next;
        }
        img[fat_base + 7 * 4..fat_base + 7 * 4 + 4]
            .copy_from_slice(&(0xFFFF_FFF8u32).to_le_bytes());

        let mut expected = Vec::new();
        for (index, cluster) in chain.into_iter().enumerate() {
            let sector = first_data_sector + (cluster as u64 - 2);
            let start = (sector * 512) as usize;
            let bytes = vec![(index + 1) as u8; 512];
            img[start..start + 512].copy_from_slice(&bytes);
            expected.extend_from_slice(&bytes);
        }

        let mut reader = ExFatReader::new(MemorySource { data: img }, 0).unwrap();

        let mut out = Vec::new();
        reader
            .read_chain(5, expected.len() as u64, &mut out)
            .unwrap();

        assert_eq!(out, expected);
    }
}

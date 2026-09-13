//! FAT32 boot sector and BIOS Parameter Block (BPB).

use crate::error::ForensisError;
use crate::result::Result;

/// Minimum FAT32 cluster count defined by the specification.
///
/// A filesystem using fewer clusters is FAT16, not FAT32.
const FAT32_MIN_CLUSTERS: u32 = 65525;

/// FAT32 8-byte type identifier present in the BPB.
const FAT32_TYPE_LABEL: &[u8; 8] = b"FAT32   ";

// FAT32 BIOS Parameter Block field offsets (per the FAT specification).
const OFF_BYTES_PER_SECTOR: usize = 0x0B;
const OFF_SECTORS_PER_CLUSTER: usize = 0x0D;
const OFF_RESERVED_SECTORS: usize = 0x0E;
const OFF_FAT_COUNT: usize = 0x10;
const OFF_ROOT_ENTRY_COUNT: usize = 0x11;
const OFF_TOTAL_SECTORS_16: usize = 0x13;
const OFF_MEDIA: usize = 0x15;
const OFF_FAT_SIZE_16: usize = 0x16;
const OFF_TOTAL_SECTORS_32: usize = 0x20;
const OFF_FAT_SIZE_32: usize = 0x24;
const OFF_ROOT_CLUSTER: usize = 0x2C;
const OFF_FS_INFO_SECTOR: usize = 0x30;
const OFF_BACKUP_BOOT_SECTOR: usize = 0x32;
const OFF_TYPE_LABEL: usize = 0x52;

/// Boot sector signature byte at offset 0x1FE.
const BOOT_SIGNATURE: u16 = 0xAA55;

/// Parses and validates the FAT32 BIOS Parameter Block.
///
/// This structure is the entry point of the FAT32 volume layout.
/// All derived geometry is computed once here so that readers and
/// investigation walks never need to reinterpret raw BPB bytes.
#[derive(Debug, Clone)]
pub struct Fat32BootSector {
    /// Bytes per sector (BPB_BytsPerSec).
    bytes_per_sector: u16,

    /// Sectors per cluster (BPB_SecPerClus).
    sectors_per_cluster: u8,

    /// Reserved sectors before the first FAT (BPB_RsvdSecCnt).
    reserved_sectors: u16,

    /// Number of FAT copies (BPB_NumFATs).
    fat_count: u8,

    /// Root directory entry count (BPB_RootEntCnt). Zero on FAT32.
    root_entry_count: u16,

    /// Volume size in sectors (BPB_TotSec32).
    total_sectors: u32,

    /// Sectors occupied by one FAT (BPB_FATSz32).
    fat_size: u32,

    /// First cluster of the root directory (BPB_RootClus).
    root_cluster: u32,

    /// Sector containing the FSInfo structure (BPB_FSInfo).
    fs_info_sector: u16,

    /// Backup boot sector (BPB_BkBootSec).
    backup_boot_sector: u16,

    /// Media descriptor byte (BS_Media).
    media: u8,

    /// Sector where the data region starts.
    first_data_sector: u32,

    /// Total number of clusters that can hold data.
    total_clusters: u32,
}

impl Fat32BootSector {
    /// Parses a FAT32 boot sector.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(ForensisError::InvalidFormat(
                "FAT32 boot sector shorter than 512 bytes".to_string(),
            ));
        }

        let signature = u16::from_le_bytes([data[0x1FE], data[0x1FF]]);

        if signature != BOOT_SIGNATURE {
            return Err(ForensisError::InvalidBootSector);
        }

        let bytes_per_sector =
            u16::from_le_bytes([data[OFF_BYTES_PER_SECTOR], data[OFF_BYTES_PER_SECTOR + 1]]);

        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(ForensisError::InvalidFormat(
                "FAT32 bytes per sector is not a supported power of two".to_string(),
            ));
        }

        let sectors_per_cluster = data[OFF_SECTORS_PER_CLUSTER];

        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(ForensisError::InvalidFormat(
                "FAT32 sectors per cluster is not a power of two".to_string(),
            ));
        }

        let reserved_sectors =
            u16::from_le_bytes([data[OFF_RESERVED_SECTORS], data[OFF_RESERVED_SECTORS + 1]]);

        let fat_count = data[OFF_FAT_COUNT];

        if fat_count == 0 {
            return Err(ForensisError::InvalidFormat(
                "FAT32 has no FAT copies".to_string(),
            ));
        }

        let root_entry_count =
            u16::from_le_bytes([data[OFF_ROOT_ENTRY_COUNT], data[OFF_ROOT_ENTRY_COUNT + 1]]);

        let total_sectors_16 =
            u16::from_le_bytes([data[OFF_TOTAL_SECTORS_16], data[OFF_TOTAL_SECTORS_16 + 1]]);

        let media = data[OFF_MEDIA];

        let fat_size_16 = u16::from_le_bytes([data[OFF_FAT_SIZE_16], data[OFF_FAT_SIZE_16 + 1]]);

        let total_sectors_32 = u32::from_le_bytes([
            data[OFF_TOTAL_SECTORS_32],
            data[OFF_TOTAL_SECTORS_32 + 1],
            data[OFF_TOTAL_SECTORS_32 + 2],
            data[OFF_TOTAL_SECTORS_32 + 3],
        ]);

        let fat_size_32 = u32::from_le_bytes([
            data[OFF_FAT_SIZE_32],
            data[OFF_FAT_SIZE_32 + 1],
            data[OFF_FAT_SIZE_32 + 2],
            data[OFF_FAT_SIZE_32 + 3],
        ]);

        let root_cluster = u32::from_le_bytes([
            data[OFF_ROOT_CLUSTER],
            data[OFF_ROOT_CLUSTER + 1],
            data[OFF_ROOT_CLUSTER + 2],
            data[OFF_ROOT_CLUSTER + 3],
        ]);

        let fs_info_sector =
            u16::from_le_bytes([data[OFF_FS_INFO_SECTOR], data[OFF_FS_INFO_SECTOR + 1]]);

        let backup_boot_sector = u16::from_le_bytes([
            data[OFF_BACKUP_BOOT_SECTOR],
            data[OFF_BACKUP_BOOT_SECTOR + 1],
        ]);

        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16 as u32
        } else {
            total_sectors_32
        };

        /*
         * FAT32 uses the 32-bit fields. FAT16 would report these
         * as zero, which is another way to reject a non-FAT32 BPB.
         */
        let fat_size = if fat_size_16 != 0 {
            fat_size_16 as u32
        } else {
            fat_size_32
        };

        if total_sectors == 0 || fat_size == 0 {
            return Err(ForensisError::InvalidBootSector);
        }

        let root_dir_sectors = (root_entry_count as u32 * 32).div_ceil(bytes_per_sector as u32);

        let fat_total_sectors = fat_size
            .checked_mul(fat_count as u32)
            .ok_or_else(|| ForensisError::InvalidFormat("FAT32 FAT size overflow".to_string()))?;

        let first_data_sector = (reserved_sectors as u32)
            .checked_add(fat_total_sectors)
            .and_then(|value| value.checked_add(root_dir_sectors))
            .ok_or_else(|| {
                ForensisError::InvalidFormat("FAT32 data region offset overflow".to_string())
            })?;

        if first_data_sector >= total_sectors {
            return Err(ForensisError::InvalidFormat(
                "FAT32 data region starts beyond the volume".to_string(),
            ));
        }

        let data_sectors = total_sectors - first_data_sector;

        let total_clusters = data_sectors / sectors_per_cluster as u32;

        let type_label = &data[OFF_TYPE_LABEL..OFF_TYPE_LABEL + 8];

        let is_fat32 = total_clusters >= FAT32_MIN_CLUSTERS || type_label == FAT32_TYPE_LABEL;

        if !is_fat32 {
            return Err(ForensisError::UnsupportedFileSystem);
        }

        if root_cluster < 2 {
            return Err(ForensisError::InvalidFormat(
                "FAT32 root cluster must be at least 2".to_string(),
            ));
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            fat_count,
            root_entry_count,
            total_sectors,
            fat_size,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
            media,
            first_data_sector,
            total_clusters,
        })
    }

    /// Returns the bytes per sector.
    pub fn bytes_per_sector(&self) -> u16 {
        self.bytes_per_sector
    }

    /// Returns the sectors per cluster.
    pub fn sectors_per_cluster(&self) -> u8 {
        self.sectors_per_cluster
    }

    /// Returns the number of reserved sectors.
    pub fn reserved_sectors(&self) -> u16 {
        self.reserved_sectors
    }

    /// Returns the number of FAT copies.
    pub fn fat_count(&self) -> u8 {
        self.fat_count
    }

    /// Returns the volume size in sectors.
    pub fn total_sectors(&self) -> u32 {
        self.total_sectors
    }

    /// Returns the number of sectors occupied by one FAT.
    pub fn fat_size(&self) -> u32 {
        self.fat_size
    }

    /// Returns the first cluster of the root directory.
    pub fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    /// Returns the sector containing the FSInfo structure.
    pub fn fs_info_sector(&self) -> u16 {
        self.fs_info_sector
    }

    /// Returns the media descriptor byte.
    pub fn media(&self) -> u8 {
        self.media
    }

    /// Returns the root directory entry count.
    ///
    /// FAT32 keeps the root directory in clusters, so this value is
    /// normally zero.
    pub fn root_entry_count(&self) -> u16 {
        self.root_entry_count
    }

    /// Returns the sector containing the backup boot sector.
    pub fn backup_boot_sector(&self) -> u16 {
        self.backup_boot_sector
    }

    /// Returns the number of bytes contained in one cluster.
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// Returns the number of 512-byte sectors contained in one cluster.
    pub fn sectors_per_cluster_u64(&self) -> u64 {
        self.sectors_per_cluster as u64
    }

    /// Returns the partition-relative sector where the data region starts.
    pub fn first_data_sector(&self) -> u64 {
        self.first_data_sector as u64
    }

    /// Returns the total number of data clusters.
    pub fn total_clusters(&self) -> u64 {
        self.total_clusters as u64
    }

    /// Returns the first partition-relative sector of a cluster.
    ///
    /// Clusters start at two: the first two FAT entries are reserved.
    pub fn sector_of_cluster(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 {
            return None;
        }

        let delta = u64::from(cluster - 2).checked_mul(self.sectors_per_cluster as u64)?;

        self.first_data_sector().checked_add(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_sector() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        data[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        data[0x0D] = 4;
        data[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes());
        data[0x10] = 2;
        data[0x20..0x24].copy_from_slice(&(64u32 * 1024 * 1024 / 512).to_le_bytes());
        data[0x24..0x28].copy_from_slice(&512u32.to_le_bytes());
        data[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes());
        data[0x52..0x5A].copy_from_slice(b"FAT32   ");
        data[0x1FE] = 0x55;
        data[0x1FF] = 0xAA;

        data
    }

    #[test]
    fn parses_valid_boot_sector() {
        let boot = Fat32BootSector::parse(&boot_sector()).unwrap();

        assert_eq!(boot.bytes_per_sector(), 512);
        assert_eq!(boot.sectors_per_cluster(), 4);
        assert_eq!(boot.reserved_sectors(), 32);
        assert_eq!(boot.fat_count(), 2);
        assert_eq!(boot.root_cluster(), 2);

        assert_eq!(boot.cluster_size(), 2048);
        assert_eq!(boot.first_data_sector(), 32 + 512 * 2);
        assert_eq!(boot.sector_of_cluster(2), Some(32 + 1024));
    }

    #[test]
    fn rejects_missing_boot_signature() {
        let mut data = boot_sector();
        data[0x1FE] = 0x00;

        let result = Fat32BootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::InvalidBootSector)));
    }

    #[test]
    fn rejects_non_fat32_cluster_count() {
        let mut data = boot_sector();
        data[0x20..0x24].copy_from_slice(&(2000u32 * 4).to_le_bytes());
        data[0x52..0x5A].copy_from_slice(b"FAT16   ");

        let result = Fat32BootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::UnsupportedFileSystem)));
    }

    #[test]
    fn rejects_zero_fat_size() {
        let mut data = boot_sector();
        data[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let result = Fat32BootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::InvalidBootSector)));
    }
}

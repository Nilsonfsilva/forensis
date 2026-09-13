//! exFAT boot sector and Extended BIOS Parameter Block.
//!
//! exFAT derives all volume geometry from the boot sector plus the
//! sector and cluster sizes encoded as bit shifts. Unlike FAT32 there
//! are no resolver-dependent fields (root entry count, FAT size in 16
//! bits): every value is stored at its explicit offset.

use crate::error::ForensisError;
use crate::result::Result;

/// exFAT 8-byte filesystem name present in the boot sector.
const EXFAT_TYPE_LABEL: &[u8; 8] = b"EXFAT   ";

// exFAT boot sector field offsets (per the exFAT specification).
const OFF_FILE_SYSTEM_NAME: usize = 0x03;
const OFF_FAT_OFFSET: usize = 0x50;
const OFF_FAT_LENGTH: usize = 0x54;
const OFF_CLUSTER_HEAP_OFFSET: usize = 0x58;
const OFF_CLUSTER_COUNT: usize = 0x5C;
const OFF_ROOT_DIRECTORY_CLUSTER: usize = 0x60;
const OFF_VOLUME_SERIAL: usize = 0x64;
const OFF_FILE_SYSTEM_REVISION: usize = 0x68;
const OFF_VOLUME_FLAGS: usize = 0x6A;
const OFF_BYTES_PER_SECTOR_SHIFT: usize = 0x6C;
const OFF_SECTORS_PER_CLUSTER_SHIFT: usize = 0x6D;
const OFF_NUMBER_OF_FATS: usize = 0x6E;
const OFF_DRIVE_SELECT: usize = 0x6F;
const OFF_PERCENT_IN_USE: usize = 0x70;

/// Boot sector signature byte at offset 0x1FE.
const BOOT_SIGNATURE: u16 = 0xAA55;

/// Supported bytes per sector (must be a power of two of at least 512).
const MIN_BYTES_PER_SECTOR: u32 = 512;

/// Maximum bytes per sector allowed by the specification.
const MAX_BYTES_PER_SECTOR: u32 = 4096;

/// Parses and validates the exFAT boot sector.
///
/// This structure is the entry point of the exFAT volume layout. All
/// derived geometry is computed once here so that readers and
/// investigation walks never need to reinterpret raw BPB bytes.
#[derive(Debug, Clone)]
pub struct ExFatBootSector {
    /// Sector size in bytes (`1 << BytesPerSectorShift`).
    bytes_per_sector: u32,

    /// Sectors per cluster (`1 << SectorsPerClusterShift`).
    sectors_per_cluster_bits: u8,

    /// Number of sectors occupied by one FAT copy.
    fat_length: u32,

    /// Sector (from the volume start) where the FAT region begins.
    fat_offset: u32,

    /// Sector (from the volume start) where the cluster heap begins.
    cluster_heap_offset: u32,

    /// Total number of clusters in the volume.
    cluster_count: u32,

    /// First cluster of the root directory.
    root_directory_cluster: u32,

    /// Volume serial number.
    volume_serial: u32,

    /// Filesystem revision (major in the high byte).
    filesystem_revision: u16,

    /// Filesystem volume flags.
    volume_flags: u16,

    /// Number of FAT copies (must be two).
    number_of_fats: u8,

    /// Drive select byte.
    drive_select: u8,

    /// Percent in use (0xFF when unknown).
    percent_in_use: u8,
}

impl ExFatBootSector {
    /// Parses an exFAT boot sector.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(ForensisError::InvalidFormat(
                "exFAT boot sector shorter than 512 bytes".to_string(),
            ));
        }

        if &data[OFF_FILE_SYSTEM_NAME..OFF_FILE_SYSTEM_NAME + 8] != EXFAT_TYPE_LABEL {
            return Err(ForensisError::InvalidBootSector);
        }

        let signature = u16::from_le_bytes([data[0x1FE], data[0x1FF]]);

        if signature != BOOT_SIGNATURE {
            return Err(ForensisError::InvalidBootSector);
        }

        let bytes_per_sector_shift = data[OFF_BYTES_PER_SECTOR_SHIFT];

        let bytes_per_sector =
            1u32.checked_shl(bytes_per_sector_shift as u32)
                .ok_or_else(|| {
                    ForensisError::InvalidFormat("exFAT sector shift overflow".to_string())
                })?;

        if !(MIN_BYTES_PER_SECTOR..=MAX_BYTES_PER_SECTOR).contains(&bytes_per_sector) {
            return Err(ForensisError::InvalidFormat(
                "exFAT bytes per sector is not a supported power of two".to_string(),
            ));
        }

        let sectors_per_cluster_bits = data[OFF_SECTORS_PER_CLUSTER_SHIFT];

        if sectors_per_cluster_bits > 25 {
            return Err(ForensisError::InvalidFormat(
                "exFAT sectors per cluster shift out of range".to_string(),
            ));
        }

        let number_of_fats = data[OFF_NUMBER_OF_FATS];

        if !(1..=2).contains(&number_of_fats) {
            return Err(ForensisError::InvalidFormat(
                "exFAT requires one or two FAT copies".to_string(),
            ));
        }

        let fat_offset = u32::from_le_bytes([
            data[OFF_FAT_OFFSET],
            data[OFF_FAT_OFFSET + 1],
            data[OFF_FAT_OFFSET + 2],
            data[OFF_FAT_OFFSET + 3],
        ]);

        let fat_length = u32::from_le_bytes([
            data[OFF_FAT_LENGTH],
            data[OFF_FAT_LENGTH + 1],
            data[OFF_FAT_LENGTH + 2],
            data[OFF_FAT_LENGTH + 3],
        ]);

        let cluster_heap_offset = u32::from_le_bytes([
            data[OFF_CLUSTER_HEAP_OFFSET],
            data[OFF_CLUSTER_HEAP_OFFSET + 1],
            data[OFF_CLUSTER_HEAP_OFFSET + 2],
            data[OFF_CLUSTER_HEAP_OFFSET + 3],
        ]);

        let cluster_count = u32::from_le_bytes([
            data[OFF_CLUSTER_COUNT],
            data[OFF_CLUSTER_COUNT + 1],
            data[OFF_CLUSTER_COUNT + 2],
            data[OFF_CLUSTER_COUNT + 3],
        ]);

        let root_directory_cluster = u32::from_le_bytes([
            data[OFF_ROOT_DIRECTORY_CLUSTER],
            data[OFF_ROOT_DIRECTORY_CLUSTER + 1],
            data[OFF_ROOT_DIRECTORY_CLUSTER + 2],
            data[OFF_ROOT_DIRECTORY_CLUSTER + 3],
        ]);

        let volume_serial = u32::from_le_bytes([
            data[OFF_VOLUME_SERIAL],
            data[OFF_VOLUME_SERIAL + 1],
            data[OFF_VOLUME_SERIAL + 2],
            data[OFF_VOLUME_SERIAL + 3],
        ]);

        let filesystem_revision = u16::from_le_bytes([
            data[OFF_FILE_SYSTEM_REVISION],
            data[OFF_FILE_SYSTEM_REVISION + 1],
        ]);

        let volume_flags = u16::from_le_bytes([data[OFF_VOLUME_FLAGS], data[OFF_VOLUME_FLAGS + 1]]);

        let drive_select = data[OFF_DRIVE_SELECT];

        let percent_in_use = data[OFF_PERCENT_IN_USE];

        if fat_offset == 0 || fat_length == 0 || cluster_heap_offset == 0 {
            return Err(ForensisError::InvalidBootSector);
        }

        if cluster_count == 0 {
            return Err(ForensisError::InvalidBootSector);
        }

        if fat_length == 0
            || cluster_heap_offset < fat_offset + fat_length * u32::from(number_of_fats)
        {
            return Err(ForensisError::InvalidFormat(
                "exFAT cluster heap must start after both FAT copies".to_string(),
            ));
        }

        if root_directory_cluster < 2 {
            return Err(ForensisError::InvalidFormat(
                "exFAT root cluster must be at least 2".to_string(),
            ));
        }

        if root_directory_cluster > cluster_count + 1 {
            return Err(ForensisError::InvalidFormat(
                "exFAT root cluster outside the cluster heap".to_string(),
            ));
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster_bits,
            fat_length,
            fat_offset,
            cluster_heap_offset,
            cluster_count,
            root_directory_cluster,
            volume_serial,
            filesystem_revision,
            volume_flags,
            number_of_fats,
            drive_select,
            percent_in_use,
        })
    }

    /// Returns the bytes per sector.
    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Returns the sectors per cluster.
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_bits
    }

    /// Returns the number of sectors occupied by one FAT copy.
    pub fn fat_length(&self) -> u32 {
        self.fat_length
    }

    /// Returns the sector where the FAT region begins.
    pub fn fat_offset(&self) -> u32 {
        self.fat_offset
    }

    /// Returns the sector where the cluster heap begins.
    pub fn cluster_heap_offset(&self) -> u32 {
        self.cluster_heap_offset
    }

    /// Returns the total number of clusters in the volume.
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    /// Returns the first cluster of the root directory.
    pub fn root_directory_cluster(&self) -> u32 {
        self.root_directory_cluster
    }

    /// Returns the volume serial number.
    pub fn volume_serial(&self) -> u32 {
        self.volume_serial
    }

    /// Returns the filesystem revision.
    pub fn filesystem_revision(&self) -> u16 {
        self.filesystem_revision
    }

    /// Returns the volume flags.
    pub fn volume_flags(&self) -> u16 {
        self.volume_flags
    }

    /// Returns the number of FAT copies.
    pub fn number_of_fats(&self) -> u8 {
        self.number_of_fats
    }

    /// Returns the drive select byte.
    pub fn drive_select(&self) -> u8 {
        self.drive_select
    }

    /// Returns the percent in use.
    pub fn percent_in_use(&self) -> u8 {
        self.percent_in_use
    }

    /// Returns the number of bytes contained in one cluster.
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster() as u64
    }

    /// Returns the number of 512-byte sectors contained in one cluster.
    ///
    /// The forensic model reports physical sectors in 512-byte units,
    /// so the cluster geometry is converted to that scale regardless of
    /// the actual bytes per sector used by the volume.
    pub fn sectors_per_cluster_u64(&self) -> u64 {
        self.cluster_size() / 512
    }

    /// Returns the 512-based sector where the data region starts.
    pub fn first_data_sector(&self) -> u64 {
        self.cluster_heap_offset as u64 * self.bytes_per_sector as u64 / 512
    }

    /// Returns the byte offset of the cluster heap inside the volume.
    pub fn cluster_heap_byte_offset(&self) -> u64 {
        self.cluster_heap_offset as u64 * self.bytes_per_sector as u64
    }

    /// Returns the byte offset of a cluster inside the volume.
    pub fn cluster_byte_offset(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 {
            return None;
        }

        let delta = u64::from(cluster - 2).checked_mul(self.cluster_size())?;

        self.cluster_heap_byte_offset().checked_add(delta)
    }

    /// Returns the first 512-based sector of a cluster.
    ///
    /// Clusters start at two: the first two FAT entries are reserved.
    pub fn sector_of_cluster(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 {
            return None;
        }

        let delta = u64::from(cluster - 2).checked_mul(self.sectors_per_cluster_u64())?;

        self.first_data_sector().checked_add(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_sector() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        data[0x03..0x0B].copy_from_slice(b"EXFAT   ");
        data[0x40..0x48].copy_from_slice(&0u64.to_le_bytes());
        data[0x48..0x50].copy_from_slice(&(64u64 * 1024 * 1024 / 512).to_le_bytes());
        data[0x50..0x54].copy_from_slice(&128u32.to_le_bytes());
        data[0x54..0x58].copy_from_slice(&1024u32.to_le_bytes());
        data[0x58..0x5C].copy_from_slice(&(128u32 + 1024u32 * 2).to_le_bytes());
        data[0x5C..0x60].copy_from_slice(&(122879u32).to_le_bytes());
        data[0x60..0x64].copy_from_slice(&2u32.to_le_bytes());
        data[0x64..0x68].copy_from_slice(&0x11223344u32.to_le_bytes());
        data[0x68..0x6A].copy_from_slice(&0x0100u16.to_le_bytes());
        data[0x6C] = 9; // 512 bytes per sector
        data[0x6D] = 0; // 1 sector per cluster
        data[0x6E] = 2;
        data[0x1FE] = 0x55;
        data[0x1FF] = 0xAA;

        data
    }

    #[test]
    fn parses_valid_boot_sector() {
        let boot = ExFatBootSector::parse(&boot_sector()).unwrap();

        assert_eq!(boot.bytes_per_sector(), 512);
        assert_eq!(boot.sectors_per_cluster(), 1);
        assert_eq!(boot.fat_offset(), 128);
        assert_eq!(boot.fat_length(), 1024);
        assert_eq!(boot.cluster_heap_offset(), 2176);
        assert_eq!(boot.root_directory_cluster(), 2);
        assert_eq!(boot.number_of_fats(), 2);

        assert_eq!(boot.cluster_size(), 512);
        assert_eq!(boot.first_data_sector(), 2176);
        assert_eq!(boot.sector_of_cluster(2), Some(2176));
    }

    #[test]
    fn computes_sector_geometry_for_large_clusters() {
        let mut data = boot_sector();

        data[0x6C] = 12; // 4096 bytes per sector
        data[0x6D] = 3; // 8 sectors per cluster

        let boot = ExFatBootSector::parse(&data).unwrap();

        assert_eq!(boot.cluster_size(), 4096 * 8);
        assert_eq!(boot.sectors_per_cluster_u64(), 64);
        assert_eq!(boot.sector_of_cluster(2), Some(2176 * 8));
    }

    #[test]
    fn rejects_missing_exfat_signature() {
        let mut data = boot_sector();

        data[0x03..0x0B].copy_from_slice(b"FAT32   ");

        let result = ExFatBootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::InvalidBootSector)));
    }

    #[test]
    fn rejects_missing_boot_signature() {
        let mut data = boot_sector();

        data[0x1FE] = 0x00;

        let result = ExFatBootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::InvalidBootSector)));
    }

    #[test]
    fn rejects_zero_fat_copies() {
        let mut data = boot_sector();

        data[0x6E] = 0;

        let result = ExFatBootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::InvalidFormat(_))));
    }

    #[test]
    fn accepts_single_fat_copy_with_enough_heap() {
        let mut data = boot_sector();

        data[0x6E] = 1;
        data[0x58..0x5C].copy_from_slice(&(128u32 + 1024u32).to_le_bytes());

        let result = ExFatBootSector::parse(&data);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().number_of_fats(), 1);
    }

    #[test]
    fn rejects_heap_before_fats_end() {
        let mut data = boot_sector();

        data[0x58..0x5C].copy_from_slice(&100u32.to_le_bytes());

        let result = ExFatBootSector::parse(&data);

        assert!(matches!(result, Err(ForensisError::InvalidFormat(_))));
    }
}

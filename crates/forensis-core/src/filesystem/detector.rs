use crate::partition::{Mbr, Partition};
use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

use super::ext4::{Ext4Filesystem, Ext4Reader};
use super::fat32::{Fat32Filesystem, Fat32Reader};
use super::ntfs::NtfsFileSystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemType {
    Ntfs,
    Ext4,
    Fat32,
    ExFat,
    Xfs,
    Btrfs,
    HfsPlus,
    Apfs,
    Unknown,
}

impl FileSystemType {
    /// Returns true when Forensis currently has a filesystem
    /// implementation capable of forensic analysis.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Ntfs | Self::Ext4 | Self::Fat32)
    }

    /// Returns a human-readable filesystem name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ntfs => "NTFS",
            Self::Ext4 => "EXT4",
            Self::Fat32 => "FAT32",
            Self::ExFat => "exFAT",
            Self::Xfs => "XFS",
            Self::Btrfs => "BTRFS",
            Self::HfsPlus => "HFS+",
            Self::Apfs => "APFS",
            Self::Unknown => "Unknown",
        }
    }
}

pub struct FileSystemDetector;

impl FileSystemDetector {
    /// Detects the filesystem of a partition.
    pub fn detect<R: Readable>(reader: &mut R, partition: &Partition) -> Result<FileSystemType> {
        let partition_offset = partition.start_sector * 512;

        Self::detect_at(reader, partition_offset)
    }

    /// Detects the filesystem starting at a byte offset.
    pub fn detect_at<R: Readable>(reader: &mut R, offset: u64) -> Result<FileSystemType> {
        let mut boot_sector = [0u8; 512];

        reader.read_at(ByteOffset::new(offset), &mut boot_sector)?;

        if &boot_sector[3..7] == b"NTFS" {
            return Ok(FileSystemType::Ntfs);
        }

        if boot_sector.windows(5).any(|x| x == b"FAT32") {
            return Ok(FileSystemType::Fat32);
        }

        let mut superblock = [0u8; 1024];

        reader.read_at(ByteOffset::new(offset + 1024), &mut superblock)?;

        let ext_signature = u16::from_le_bytes([superblock[56], superblock[57]]);

        if ext_signature == 0xEF53 {
            return Ok(FileSystemType::Ext4);
        }

        Ok(FileSystemType::Unknown)
    }

    /// Creates an NTFS filesystem from a partition.
    ///
    /// This method must only be called after filesystem
    /// detection has confirmed NTFS support.
    pub fn open_ntfs<R: Readable>(reader: &mut R, partition: &Partition) -> Result<NtfsFileSystem> {
        let partition_offset = partition.start_sector * 512;

        Self::open_ntfs_at(reader, partition_offset)
    }

    /// Creates an NTFS filesystem starting at a byte offset.
    ///
    /// This method must only be called after filesystem
    /// detection has confirmed NTFS support.
    pub fn open_ntfs_at<R: Readable>(reader: &mut R, offset: u64) -> Result<NtfsFileSystem> {
        NtfsFileSystem::parse(reader, offset)
    }

    /// Creates an EXT4 filesystem from a partition.
    ///
    /// This method must only be called after filesystem
    /// detection has confirmed EXT4 support.
    pub fn open_ext4<R: Readable>(reader: &mut R, partition: &Partition) -> Result<Ext4Filesystem> {
        let partition_offset = partition.start_sector * 512;

        Self::open_ext4_at(reader, partition_offset)
    }

    /// Creates an EXT4 filesystem starting at a byte offset.
    ///
    /// This method must only be called after filesystem
    /// detection has confirmed EXT4 support.
    pub fn open_ext4_at<R: Readable>(reader: &mut R, offset: u64) -> Result<Ext4Filesystem> {
        let mut ext4_reader = Ext4Reader::new(reader, offset);

        Ext4Filesystem::open(&mut ext4_reader)
    }

    /// Creates a FAT32 filesystem from a partition.
    ///
    /// This method must only be called after filesystem
    /// detection has confirmed FAT32 support.
    pub fn open_fat32<R: Readable>(
        reader: &mut R,
        partition: &Partition,
    ) -> Result<Fat32Filesystem> {
        let partition_offset = partition.start_sector * 512;

        Self::open_fat32_at(reader, partition_offset)
    }

    /// Creates a FAT32 filesystem starting at a byte offset.
    ///
    /// This method must only be called after filesystem
    /// detection has confirmed FAT32 support.
    pub fn open_fat32_at<R: Readable>(reader: &mut R, offset: u64) -> Result<Fat32Filesystem> {
        let mut fat32_reader = Fat32Reader::new(reader, offset)?;

        Fat32Filesystem::open(&mut fat32_reader)
    }

    /// Returns true when an MBR partition entry contains
    /// a partition type recognized by Forensis.
    ///
    /// This keeps MBR detection consistent with the MBR parser
    /// itself and prevents filesystem boot-sector bytes from
    /// being interpreted as partition entries.
    #[allow(dead_code)]
    fn is_known_mbr_partition_type(value: u8) -> bool {
        Mbr::parse_partition_type(value) != crate::partition::PartitionType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::FileSystemType;

    #[test]
    fn ntfs_is_supported() {
        assert!(FileSystemType::Ntfs.is_supported());
    }

    #[test]
    fn ext4_is_supported() {
        assert!(FileSystemType::Ext4.is_supported());
    }

    #[test]
    fn fat32_is_supported() {
        assert!(FileSystemType::Fat32.is_supported());
    }

    #[test]
    fn exfat_is_not_supported_yet() {
        assert!(!FileSystemType::ExFat.is_supported());
    }

    #[test]
    fn future_filesystems_are_not_supported_yet() {
        assert!(!FileSystemType::Xfs.is_supported());
        assert!(!FileSystemType::Btrfs.is_supported());
        assert!(!FileSystemType::HfsPlus.is_supported());
        assert!(!FileSystemType::Apfs.is_supported());
    }

    #[test]
    fn unknown_filesystem_is_not_supported() {
        assert!(!FileSystemType::Unknown.is_supported());
    }

    #[test]
    fn filesystem_display_names_are_correct() {
        assert_eq!(FileSystemType::Ntfs.display_name(), "NTFS");
        assert_eq!(FileSystemType::Ext4.display_name(), "EXT4");
        assert_eq!(FileSystemType::Fat32.display_name(), "FAT32");
        assert_eq!(FileSystemType::ExFat.display_name(), "exFAT");
        assert_eq!(FileSystemType::Xfs.display_name(), "XFS");
        assert_eq!(FileSystemType::Btrfs.display_name(), "BTRFS");
        assert_eq!(FileSystemType::HfsPlus.display_name(), "HFS+");
        assert_eq!(FileSystemType::Apfs.display_name(), "APFS");
        assert_eq!(FileSystemType::Unknown.display_name(), "Unknown");
    }
}

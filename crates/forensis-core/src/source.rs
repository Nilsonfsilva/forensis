use std::path::{Path, PathBuf};

/// Type of evidence source available for investigation.
///
/// The enumeration describes the nature of the source without
/// depending on the operating system that provides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSourceKind {
    /// Physical storage device.
    BlockDevice,

    /// Partition of a storage device.
    Partition,

    /// File containing a forensic image.
    DiskImage,
}

/// Evidence source that can be investigated by Forensis.
///
/// This structure represents a source available before the
/// investigation starts.
///
/// It does not represent the investigation result. The result
/// continues to be represented by `forensic::ForensicSource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSource {
    path: PathBuf,
    kind: EvidenceSourceKind,
}

impl EvidenceSource {
    /// Creates a new evidence source.
    pub fn new(path: impl Into<PathBuf>, kind: EvidenceSourceKind) -> Self {
        Self {
            path: path.into(),
            kind,
        }
    }

    /// Creates a source corresponding to a block device.
    pub fn block_device(path: impl Into<PathBuf>) -> Self {
        Self::new(path, EvidenceSourceKind::BlockDevice)
    }

    /// Creates a source corresponding to a partition.
    pub fn partition(path: impl Into<PathBuf>) -> Self {
        Self::new(path, EvidenceSourceKind::Partition)
    }

    /// Creates a source corresponding to a forensic image.
    pub fn disk_image(path: impl Into<PathBuf>) -> Self {
        Self::new(path, EvidenceSourceKind::DiskImage)
    }

    /// Returns the physical path of the source.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the type of the source.
    pub fn kind(&self) -> EvidenceSourceKind {
        self.kind
    }

    /// Indicates whether the source is a block device.
    pub fn is_block_device(&self) -> bool {
        self.kind == EvidenceSourceKind::BlockDevice
    }

    /// Indicates whether the source is a partition.
    pub fn is_partition(&self) -> bool {
        self.kind == EvidenceSourceKind::Partition
    }

    /// Indicates whether the source is a forensic image.
    pub fn is_disk_image(&self) -> bool {
        self.kind == EvidenceSourceKind::DiskImage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_device_source_is_created_correctly() {
        let source = EvidenceSource::block_device("/dev/nvme0n1");

        assert_eq!(source.path(), Path::new("/dev/nvme0n1"));

        assert_eq!(source.kind(), EvidenceSourceKind::BlockDevice);

        assert!(source.is_block_device());
        assert!(!source.is_partition());
        assert!(!source.is_disk_image());
    }

    #[test]
    fn partition_source_is_created_correctly() {
        let source = EvidenceSource::partition("/dev/nvme0n1p2");

        assert_eq!(source.path(), Path::new("/dev/nvme0n1p2"));

        assert_eq!(source.kind(), EvidenceSourceKind::Partition);

        assert!(source.is_partition());
        assert!(!source.is_block_device());
        assert!(!source.is_disk_image());
    }

    #[test]
    fn disk_image_source_is_created_correctly() {
        let source = EvidenceSource::disk_image("evidence.img");

        assert_eq!(source.path(), Path::new("evidence.img"));

        assert_eq!(source.kind(), EvidenceSourceKind::DiskImage);

        assert!(!source.is_block_device());
        assert!(!source.is_partition());
        assert!(source.is_disk_image());
    }

    #[test]
    fn sources_with_same_path_and_kind_are_equal() {
        let first = EvidenceSource::disk_image("disk.img");

        let second = EvidenceSource::new("disk.img", EvidenceSourceKind::DiskImage);

        assert_eq!(first, second);
    }
}

//! Core traits that define common behaviors across Forensis modules.

use crate::result::Result;
use crate::types::{ByteOffset, ByteSize};

/// Defines a source capable of random access reading.
///
/// Implementations may represent physical disks, forensic images,
/// virtual disks, or any other storage backend.
pub trait Readable {
    /// Reads bytes starting from an absolute byte offset.
    fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()>;

    /// Returns the total size of the readable source.
    fn size(&self) -> ByteSize;
}

/// Allows a mutable reference to a readable source
/// to be used as a readable source itself.
///
/// This enables filesystem readers to wrap an already
/// borrowed source without requiring ownership.
impl<R: Readable> Readable for &mut R {
    fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buffer)
    }

    fn size(&self) -> ByteSize {
        (**self).size()
    }
}

/// Defines a storage device abstraction.
///
/// A Disk implementation represents metadata and access information
/// about a storage medium.
pub trait Storage {
    /// Returns the storage name.
    fn name(&self) -> &str;

    /// Returns the storage size.
    fn size(&self) -> ByteSize;
}

/// Defines a filesystem parser.
///
/// Each filesystem implementation (NTFS, FAT32, EXT4, etc.)
/// must implement this trait.
pub trait FileSystem {
    /// Detects whether this filesystem matches the provided data.
    fn detect(buffer: &[u8]) -> bool;

    /// Returns the filesystem name.
    fn name(&self) -> &str;
}

pub trait PartitionTableReader {
    fn partitions(&self) -> &[crate::partition::Partition];
}

/// Defines a data carving engine.
///
/// Used to recover files without filesystem metadata.
pub trait Carver {
    /// Searches raw storage for recoverable file signatures.
    fn carve(&self) -> Result<()>;
}

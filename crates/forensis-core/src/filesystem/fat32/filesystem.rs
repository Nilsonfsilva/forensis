//! FAT32 filesystem top-level representation.
use crate::progress::ProgressReporter;
use crate::result::Result;
use crate::traits::Readable;

use super::{
    investigate_filesystem, investigate_filesystem_with_progress, Fat32BootSector,
    Fat32Investigation, Fat32Reader,
};

/// Represents a FAT32 filesystem.
///
/// The whole FAT32 configuration lives in the boot sector, so this
/// structure wraps the parsed BPB and provides the top-level operations
/// needed by the detector and the application layer.
#[derive(Debug, Clone)]
pub struct Fat32Filesystem {
    boot: Fat32BootSector,
}

impl Fat32Filesystem {
    /// Creates a FAT32 filesystem representation.
    pub fn new(boot: Fat32BootSector) -> Self {
        Self { boot }
    }

    /// Opens a FAT32 filesystem using an existing reader.
    ///
    /// The boot sector is already parsed by the reader, so this only
    /// captures the parsed configuration.
    pub fn open<R: Readable>(reader: &mut Fat32Reader<R>) -> Result<Self> {
        Ok(Self {
            boot: reader.boot().clone(),
        })
    }

    /// Returns the FAT32 boot sector.
    pub fn boot(&self) -> &Fat32BootSector {
        &self.boot
    }

    /// Returns the cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.boot.cluster_size()
    }

    /// Investigates the FAT32 filesystem without progress reporting.
    ///
    /// This compatibility API intentionally keeps the existing behavior.
    /// Progress reporting is disabled through `NoProgress`.
    pub fn investigate<R: Readable>(
        &self,
        reader: &mut Fat32Reader<R>,
    ) -> Result<Fat32Investigation> {
        investigate_filesystem(reader)
    }

    /// Investigates the FAT32 filesystem and reports progress.
    ///
    /// FAT32 directory traversal does not know the final number of
    /// directory clusters in advance, so progress is reported as an
    /// indeterminate counter of directory clusters processed.
    pub fn investigate_with_progress<R: Readable>(
        &self,
        reader: &mut Fat32Reader<R>,
        reporter: &dyn ProgressReporter,
    ) -> Result<Fat32Investigation> {
        investigate_filesystem_with_progress(reader, reporter)
    }
}

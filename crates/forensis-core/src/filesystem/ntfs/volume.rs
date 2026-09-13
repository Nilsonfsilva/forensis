use crate::progress::ProgressReporter;
use crate::result::Result;
use crate::traits::Readable;

use super::boot_sector::NtfsFileSystem;
use super::investigation::Investigation;

/// Represents an NTFS volume.
pub struct NtfsVolume {
    filesystem: NtfsFileSystem,
}

impl NtfsVolume {
    /// Creates a volume from an already parsed NTFS filesystem.
    pub fn new(filesystem: NtfsFileSystem) -> Self {
        Self { filesystem }
    }

    /// Returns the underlying NTFS filesystem.
    pub fn filesystem(&self) -> &NtfsFileSystem {
        &self.filesystem
    }

    /// Investigates the complete NTFS volume.
    ///
    /// The number of MFT records is determined
    /// automatically from the real size of $MFT.
    ///
    /// Progress reporting is disabled for this compatibility API.
    pub fn investigate<R: Readable>(&self, reader: &mut R) -> Result<Investigation> {
        self.filesystem.investigate(reader)
    }

    /// Investigates the complete NTFS volume and reports progress.
    pub fn investigate_with_progress<R: Readable>(
        &self,
        reader: &mut R,
        reporter: &dyn ProgressReporter,
    ) -> Result<Investigation> {
        self.filesystem.investigate_with_progress(reader, reporter)
    }
}

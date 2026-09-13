//! exFAT filesystem top-level representation.

use crate::result::Result;
use crate::traits::Readable;

use super::{investigate_filesystem, ExFatBootSector, ExFatInvestigation, ExFatReader};

/// Represents an exFAT filesystem.
///
/// The whole exFAT configuration lives in the boot sector, so this
/// structure wraps the parsed BPB and provides the top-level operations
/// needed by the detector and the application layer.
#[derive(Debug, Clone)]
pub struct ExFatFilesystem {
    boot: ExFatBootSector,
}

impl ExFatFilesystem {
    /// Creates an exFAT filesystem representation.
    pub fn new(boot: ExFatBootSector) -> Self {
        Self { boot }
    }

    /// Opens an exFAT filesystem using an existing reader.
    ///
    /// The boot sector is already parsed by the reader, so this only
    /// captures the parsed configuration.
    pub fn open<R: Readable>(reader: &mut ExFatReader<R>) -> Result<Self> {
        Ok(Self {
            boot: reader.boot().clone(),
        })
    }

    /// Returns the exFAT boot sector.
    pub fn boot(&self) -> &ExFatBootSector {
        &self.boot
    }

    /// Returns the cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.boot.cluster_size()
    }

    /// Investigates the exFAT filesystem.
    ///
    /// The walk starts at the root directory and descends the whole
    /// directory hierarchy, recovering deleted entries through their
    /// residual directory slots and FAT chains.
    pub fn investigate<R: Readable>(
        &self,
        reader: &mut ExFatReader<R>,
    ) -> Result<ExFatInvestigation> {
        investigate_filesystem(reader)
    }
}

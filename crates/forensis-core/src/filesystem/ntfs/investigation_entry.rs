use super::data_attribute::DataAttribute;
use super::data_run::DataRun;
use super::file_name::FileNameAttribute;

use crate::forensic::{
    ForensicAllocation, ForensicContentLayout, ForensicContentSegment, ForensicEntry,
    ForensicEntryKind, ForensicFilesystem, ForensicHierarchy, ForensicIdentity, ForensicMetadata,
    ForensicObject, ForensicPhysicalLocation, ForensicPhysicalRegion, ForensicStatus,
};

/// NTFS FILE_ATTRIBUTE_DIRECTORY.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10000000;

/// NTFS FILE_ATTRIBUTE_SYSTEM.
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;

/// NTFS MFT record flag: record is in use.
const MFT_RECORD_IN_USE: u16 = 0x0001;

/// NTFS uses 512-byte sectors in the forensic image.
const NTFS_BYTES_PER_SECTOR: u64 = 512;

/// Represents an item discovered during filesystem investigation.
#[derive(Debug, Clone)]
pub struct InvestigationEntry {
    /// MFT record number.
    pub mft_record: u64,

    /// Parent directory MFT record number.
    pub parent_mft_record: u64,

    /// File or directory name.
    pub name: String,

    /// Allocated size on disk.
    pub allocated_size: u64,

    /// Real file size.
    pub real_size: u64,

    /// NTFS file attributes.
    pub flags: u32,

    /// MFT record flags.
    pub mft_flags: u16,

    /// Indicates whether this entry represents a directory.
    pub is_directory: bool,

    /// NTFS data runs describing the physical allocation.
    pub data_runs: Vec<DataRun>,

    /// Resident NTFS DATA bytes stored directly inside the MFT record.
    ///
    /// Resident data has no physical data-run allocation. The bytes
    /// are therefore represented as inline content in the generic
    /// forensic model.
    pub resident_data: Option<Vec<u8>>,
}

impl InvestigationEntry {
    /// Creates an investigation entry from an NTFS FILE_NAME
    /// attribute when the MFT allocation state is not available.
    ///
    /// This constructor is retained for directory structures
    /// that provide FILE_NAME information without the complete
    /// MFT record.
    ///
    /// Such an entry cannot be considered deleted merely because
    /// the MFT flags are unavailable. It is therefore marked as
    /// in use for compatibility with this limited source.
    pub fn from_file_name(mft_record: u64, file_name: &FileNameAttribute) -> Self {
        Self {
            mft_record,
            parent_mft_record: file_name.parent_record,
            name: file_name.name.clone(),
            allocated_size: file_name.allocated_size,
            real_size: file_name.real_size,
            flags: file_name.file_attributes,
            mft_flags: MFT_RECORD_IN_USE,
            is_directory: file_name.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            data_runs: Vec::new(),
            resident_data: None,
        }
    }

    /// Creates an investigation entry from FILE_NAME, DATA and
    /// MFT record flags belonging to the same MFT record.
    ///
    /// This is the authoritative constructor for entries produced
    /// directly from MFT records because the allocation state is
    /// derived from the real MFT flags.
    pub fn from_file_name_and_data(
        mft_record: u64,
        file_name: &FileNameAttribute,
        data: Option<&DataAttribute>,
        mft_flags: u16,
    ) -> Self {
        let (real_size, allocated_size, data_runs, resident_data) = match data {
            Some(data_attribute) => (
                data_attribute.real_size,
                data_attribute.allocated_size,
                data_attribute.data_runs.clone(),
                data_attribute.resident_data.clone(),
            ),

            None => (
                file_name.real_size,
                file_name.allocated_size,
                Vec::new(),
                None,
            ),
        };

        Self {
            mft_record,
            parent_mft_record: file_name.parent_record,
            name: file_name.name.clone(),
            allocated_size,
            real_size,
            flags: file_name.file_attributes,
            mft_flags,
            is_directory: file_name.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            data_runs,
            resident_data,
        }
    }

    /// Converts NTFS data runs into filesystem-independent
    /// physical forensic regions.
    ///
    /// Sparse runs are deliberately omitted because they do
    /// not correspond to physical regions on the image.
    fn physical_location(&self, sectors_per_cluster: u64) -> ForensicPhysicalLocation {
        let mut location = ForensicPhysicalLocation::empty();

        if sectors_per_cluster == 0 {
            return location;
        }

        for run in &self.data_runs {
            let lcn_start = match run.lcn {
                Some(value) if value >= 0 => value as u64,

                Some(_) => continue,

                None => continue,
            };

            let cluster_end = match lcn_start.checked_add(run.cluster_count.saturating_sub(1)) {
                Some(value) => value,

                None => continue,
            };

            let sector_start = match lcn_start.checked_mul(sectors_per_cluster) {
                Some(value) => value,

                None => continue,
            };

            let sector_count = match run.cluster_count.checked_mul(sectors_per_cluster) {
                Some(value) => value,

                None => continue,
            };

            let sector_end = match sector_start.checked_add(sector_count.saturating_sub(1)) {
                Some(value) => value,

                None => continue,
            };

            location.add_region(ForensicPhysicalRegion::from_ranges(
                lcn_start,
                cluster_end,
                sector_start,
                sector_end,
                None,
            ));
        }

        location
    }

    /// Converts the NTFS data runs into the logical content
    /// sequence consumed by the generic forensic model.
    ///
    /// The logical position is expressed in clusters.
    ///
    /// Resident data is represented as inline content because
    /// its bytes are stored directly inside the NTFS MFT record
    /// and therefore have no physical data-run region.
    ///
    /// Physical runs contain a reference to their physical
    /// forensic region.
    ///
    /// Sparse runs have no physical region and are represented
    /// explicitly so that recovery can reconstruct their logical
    /// zero-filled content in the correct position.
    fn content_layout(&self, sectors_per_cluster: u64) -> ForensicContentLayout {
        if sectors_per_cluster == 0 {
            return ForensicContentLayout::empty();
        }

        let bytes_per_cluster = match sectors_per_cluster.checked_mul(NTFS_BYTES_PER_SECTOR) {
            Some(value) => value,

            None => {
                return ForensicContentLayout::empty();
            }
        };

        /*
         * Resident NTFS DATA is already present in memory as the
         * exact logical file bytes. It must not be represented as
         * a physical region and must not be expanded to a full
         * cluster.
         *
         * For example, a resident file containing 10 bytes must
         * remain a 10-byte logical segment, not become 4096 bytes
         * merely because one cluster is 4096 bytes.
         */
        if let Some(data) = &self.resident_data {
            return ForensicContentLayout::new(
                bytes_per_cluster,
                vec![ForensicContentSegment::inline(
                    0,
                    data.clone(),
                    bytes_per_cluster,
                )],
            );
        }

        let mut segments = Vec::new();

        let mut logical_cluster_start = 0u64;

        for run in &self.data_runs {
            if run.cluster_count == 0 {
                continue;
            }

            let physical_region = self.physical_region_for_run(run, sectors_per_cluster);

            let segment = match physical_region {
                Some(region) => ForensicContentSegment::physical(
                    logical_cluster_start,
                    run.cluster_count,
                    region,
                ),

                None => {
                    /*
                     * In NTFS, an absent LCN means that
                     * the run is sparse. Its logical content
                     * consists of zero bytes and has no
                     * physical storage location.
                     */
                    ForensicContentSegment::sparse(logical_cluster_start, run.cluster_count)
                }
            };

            segments.push(segment);

            logical_cluster_start = match logical_cluster_start.checked_add(run.cluster_count) {
                Some(value) => value,

                None => {
                    return ForensicContentLayout::empty();
                }
            };
        }

        ForensicContentLayout::new(bytes_per_cluster, segments)
    }

    /// Converts one non-sparse NTFS run into a physical
    /// forensic region.
    fn physical_region_for_run(
        &self,
        run: &DataRun,
        sectors_per_cluster: u64,
    ) -> Option<ForensicPhysicalRegion> {
        let lcn_start = match run.lcn {
            Some(value) if value >= 0 => value as u64,

            _ => return None,
        };

        let cluster_end = lcn_start.checked_add(run.cluster_count.saturating_sub(1))?;

        let sector_start = lcn_start.checked_mul(sectors_per_cluster)?;

        let sector_count = run.cluster_count.checked_mul(sectors_per_cluster)?;

        let sector_end = sector_start.checked_add(sector_count.saturating_sub(1))?;

        Some(ForensicPhysicalRegion::from_ranges(
            lcn_start,
            cluster_end,
            sector_start,
            sector_end,
            None,
        ))
    }

    /// Converts the NTFS-specific investigation entry into
    /// the filesystem-independent forensic model.
    pub fn to_forensic_entry(&self, sectors_per_cluster: u64) -> ForensicEntry {
        let kind = if self.is_directory {
            ForensicEntryKind::Directory
        } else {
            ForensicEntryKind::File
        };

        /*
         * The allocation state of an NTFS object is determined
         * from the MFT record flags.
         *
         * FILE_ATTRIBUTE_SYSTEM belongs to the FILE_NAME metadata.
         *
         * The allocated/deleted state belongs to the MFT record.
         */
        let status = if self.mft_flags & MFT_RECORD_IN_USE == 0 {
            ForensicStatus::Deleted
        } else if self.flags & FILE_ATTRIBUTE_SYSTEM != 0 {
            ForensicStatus::System
        } else {
            ForensicStatus::Normal
        };

        let identity = ForensicIdentity::new(
            self.name.clone(),
            String::new(),
            kind,
            status,
            self.mft_record,
        );

        let hierarchy = ForensicHierarchy::new(Some(self.parent_mft_record));

        let metadata = ForensicMetadata::new(Some(self.real_size), Some(self.allocated_size));

        let filesystem_object = ForensicObject::new(ForensicFilesystem::Ntfs, self.mft_record);

        let cluster_count = if self.data_runs.is_empty() {
            None
        } else {
            Some(self.data_runs.iter().map(|run| run.cluster_count).sum())
        };

        let allocation = ForensicAllocation {
            allocated: Some(self.mft_flags & MFT_RECORD_IN_USE != 0),
            cluster_count,
            bitmap_allocated: None,
        };

        let physical_location = self.physical_location(sectors_per_cluster);

        let content_layout = self.content_layout(sectors_per_cluster);

        ForensicEntry::new(
            identity,
            hierarchy,
            metadata,
            filesystem_object,
            allocation,
            physical_location,
        )
        .with_content_layout(content_layout)
    }
}

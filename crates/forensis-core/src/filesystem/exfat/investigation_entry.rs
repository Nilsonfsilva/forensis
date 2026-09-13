//! exFAT investigation entry and forensic model mapping.
//!
//! An exFAT object is described by its directory record (name, size,
//! attributes, first cluster) plus the FAT chain that maps the logical
//! clusters to the physical data region. This module converts that
//! representation into the filesystem-independent forensic model.

use chrono::{DateTime, Utc};

use crate::forensic::{
    ForensicAllocation, ForensicContentLayout, ForensicContentSegment, ForensicEntry,
    ForensicEntryKind, ForensicFilesystem, ForensicHierarchy, ForensicIdentity, ForensicMetadata,
    ForensicObject, ForensicPhysicalLocation, ForensicPhysicalRegion, ForensicStatus,
};

use super::directory::ExFatEntryKind;

/// Represents an item discovered during an exFAT investigation.
///
/// This structure belongs exclusively to the exFAT layer. The
/// filesystem-independent forensic model is obtained exclusively
/// through `to_forensic_entry()`.
#[derive(Debug, Clone)]
pub struct ExFatInvestigationEntry {
    object_id: u64,
    parent_id: u64,
    name: String,
    kind: ExFatEntryKind,
    deleted: bool,
    real_size: u64,
    attributes: u8,
    cluster: u32,
    chain: Vec<u32>,
    created_at: Option<DateTime<Utc>>,
    modified_at: Option<DateTime<Utc>>,
    accessed_at: Option<DateTime<Utc>>,
}

impl ExFatInvestigationEntry {
    /// Creates an exFAT investigation entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        object_id: u64,
        parent_id: u64,
        name: String,
        kind: ExFatEntryKind,
        deleted: bool,
        real_size: u64,
        attributes: u8,
        cluster: u32,
        chain: Vec<u32>,
        created_at: Option<DateTime<Utc>>,
        modified_at: Option<DateTime<Utc>>,
        accessed_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            object_id,
            parent_id,
            name,
            kind,
            deleted,
            real_size,
            attributes,
            cluster,
            chain,
            created_at,
            modified_at,
            accessed_at,
        }
    }

    /// Returns the object identifier assigned during the investigation.
    pub fn object_id(&self) -> u64 {
        self.object_id
    }

    /// Returns the starting cluster of the parent directory.
    pub fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Returns the entry name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the record kind.
    pub fn kind(&self) -> ExFatEntryKind {
        self.kind
    }

    /// Returns true when the entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.kind == ExFatEntryKind::Directory
    }

    /// Returns true when the entry is a filesystem system entry.
    pub fn is_system(&self) -> bool {
        matches!(
            self.kind,
            ExFatEntryKind::AllocationBitmap | ExFatEntryKind::UpCaseTable
        )
    }

    /// Returns true when the entry is the volume label.
    pub fn is_volume_label(&self) -> bool {
        self.kind == ExFatEntryKind::VolumeLabel
    }

    /// Returns true when the entry has been deleted.
    pub fn deleted(&self) -> bool {
        self.deleted
    }

    /// Returns the file size recorded in the stream extension.
    pub fn real_size(&self) -> u64 {
        self.real_size
    }

    /// Returns the raw attribute byte.
    pub fn attributes(&self) -> u8 {
        self.attributes
    }

    /// Returns the first cluster number.
    pub fn cluster(&self) -> u32 {
        self.cluster
    }

    /// Returns the resolved FAT chain of the entry.
    pub fn chain(&self) -> &[u32] {
        &self.chain
    }

    /// Returns the creation timestamp.
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        self.created_at
    }

    /// Returns the last modification timestamp.
    pub fn modified_at(&self) -> Option<DateTime<Utc>> {
        self.modified_at
    }

    /// Returns the last access timestamp.
    pub fn accessed_at(&self) -> Option<DateTime<Utc>> {
        self.accessed_at
    }

    /// Returns true when the entry has no valid data allocation.
    fn is_unallocated(&self) -> bool {
        self.chain.is_empty()
    }

    /// Merges consecutive chain clusters into physical regions.
    ///
    /// Sectors are partition-relative 512-byte sectors, following the
    /// convention used by the recovery engine.
    fn physical_location(
        &self,
        sectors_per_cluster: u64,
        first_data_sector: u64,
    ) -> ForensicPhysicalLocation {
        let mut location = ForensicPhysicalLocation::empty();

        if sectors_per_cluster == 0 {
            return location;
        }

        let mut run_start: Option<(u32, u32)> = None;

        for cluster in &self.chain {
            match run_start {
                None => run_start = Some((*cluster, *cluster)),
                Some((start, previous)) => {
                    if *cluster == previous.wrapping_add(1) {
                        run_start = Some((start, *cluster));
                    } else {
                        if let Some(region) = self.region_for_run(
                            start,
                            previous,
                            sectors_per_cluster,
                            first_data_sector,
                        ) {
                            location.add_region(region);
                        }

                        run_start = Some((*cluster, *cluster));
                    }
                }
            }
        }

        if let Some((start, end)) = run_start {
            if let Some(region) =
                self.region_for_run(start, end, sectors_per_cluster, first_data_sector)
            {
                location.add_region(region);
            }
        }

        location
    }

    /// Converts one contiguous cluster run into a physical region.
    fn region_for_run(
        &self,
        start: u32,
        end: u32,
        sectors_per_cluster: u64,
        first_data_sector: u64,
    ) -> Option<ForensicPhysicalRegion> {
        if start < 2 || end < start || sectors_per_cluster == 0 {
            return None;
        }

        let sector_start = first_data_sector
            .checked_add(u64::from(start - 2).checked_mul(sectors_per_cluster)?)?;

        let sector_end = first_data_sector
            .checked_add(u64::from(end - 2).checked_mul(sectors_per_cluster)?)?
            .checked_add(sectors_per_cluster.saturating_sub(1))?;

        Some(ForensicPhysicalRegion::from_ranges(
            u64::from(start),
            u64::from(end),
            sector_start,
            sector_end,
            None,
        ))
    }

    /// Converts the FAT chain into the logical content sequence.
    fn content_layout(
        &self,
        bytes_per_cluster: u64,
        sectors_per_cluster: u64,
        first_data_sector: u64,
    ) -> ForensicContentLayout {
        if bytes_per_cluster == 0 || self.chain.is_empty() {
            return ForensicContentLayout::empty();
        }

        let mut segments = Vec::new();

        let mut logical_cluster_start = 0u64;

        let mut run_start = self.chain[0];

        let mut run_length = 1u64;

        let mut previous = self.chain[0];

        for cluster in &self.chain[1..] {
            match cluster {
                next if *next == previous.wrapping_add(1) => run_length += 1,
                next => {
                    if let Some(region) = self.region_for_run(
                        run_start,
                        previous,
                        sectors_per_cluster,
                        first_data_sector,
                    ) {
                        segments.push(ForensicContentSegment::physical(
                            logical_cluster_start,
                            run_length,
                            region,
                        ));
                    } else {
                        segments.push(ForensicContentSegment::sparse(
                            logical_cluster_start,
                            run_length,
                        ));
                    }

                    logical_cluster_start += run_length;

                    run_start = *next;
                    run_length = 1;
                }
            }

            previous = *cluster;
        }

        if let Some(region) =
            self.region_for_run(run_start, previous, sectors_per_cluster, first_data_sector)
        {
            segments.push(ForensicContentSegment::physical(
                logical_cluster_start,
                run_length,
                region,
            ));
        } else {
            segments.push(ForensicContentSegment::sparse(
                logical_cluster_start,
                run_length,
            ));
        }

        ForensicContentLayout::new(bytes_per_cluster, segments)
    }

    /// Converts the exFAT-specific entry into the forensic model.
    ///
    /// `bytes_per_cluster`, `sectors_per_cluster` and `first_data_sector`
    /// come from the boot sector; the latter anchors the partition-relative
    /// sector mapping.
    pub fn to_forensic_entry(
        &self,
        bytes_per_cluster: u64,
        sectors_per_cluster: u64,
        first_data_sector: u64,
    ) -> ForensicEntry {
        let kind = if self.is_volume_label() || self.is_system() {
            ForensicEntryKind::Other
        } else if self.is_directory() {
            ForensicEntryKind::Directory
        } else {
            ForensicEntryKind::File
        };

        let status = if self.deleted {
            ForensicStatus::Deleted
        } else if self.is_volume_label() || self.is_system() {
            ForensicStatus::System
        } else if self.real_size > 0 && self.is_unallocated() {
            ForensicStatus::Inconsistent
        } else {
            ForensicStatus::Normal
        };

        let identity = ForensicIdentity::new(
            self.name.clone(),
            String::new(),
            kind,
            status,
            self.object_id,
        );

        let hierarchy = ForensicHierarchy::new(Some(self.parent_id));

        let metadata = ForensicMetadata::new(
            Some(self.real_size),
            Some(self.chain.len() as u64 * bytes_per_cluster),
        )
        .with_timestamps(self.created_at, self.modified_at, self.accessed_at);

        let filesystem_object = ForensicObject::new(ForensicFilesystem::ExFat, self.cluster as u64);

        let allocation = ForensicAllocation {
            allocated: Some(!self.deleted),
            cluster_count: Some(self.chain.len() as u64),
            bitmap_allocated: None,
        };

        let physical_location = self.physical_location(sectors_per_cluster, first_data_sector);

        let content_layout =
            self.content_layout(bytes_per_cluster, sectors_per_cluster, first_data_sector);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::model::ForensicContentSource;

    const CLUSTER_SIZE: u64 = 4096;
    const SECTORS_PER_CLUSTER: u64 = 8;
    const FIRST_DATA_SECTOR: u64 = 2176;

    #[allow(clippy::too_many_arguments)]
    fn entry(
        object_id: u64,
        parent: u64,
        name: &str,
        kind: ExFatEntryKind,
        deleted: bool,
        real_size: u64,
        cluster: u32,
        chain: Vec<u32>,
    ) -> ExFatInvestigationEntry {
        ExFatInvestigationEntry::new(
            object_id,
            parent,
            name.to_string(),
            kind,
            deleted,
            real_size,
            0x20,
            cluster,
            chain,
            None,
            None,
            None,
        )
    }

    fn to_forensic(entry: &ExFatInvestigationEntry) -> ForensicEntry {
        entry.to_forensic_entry(CLUSTER_SIZE, SECTORS_PER_CLUSTER, FIRST_DATA_SECTOR)
    }

    #[test]
    fn regular_file_maps_to_normal() {
        let entry = entry(
            1,
            2,
            "relatorio.txt",
            ExFatEntryKind::File,
            false,
            8192,
            42,
            vec![42, 43],
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.name, "relatorio.txt");
        assert_eq!(forensic.identity.kind, ForensicEntryKind::File);
        assert_eq!(forensic.identity.status, ForensicStatus::Normal);
        assert_eq!(forensic.identity.object_id, 1);
        assert_eq!(forensic.hierarchy.parent_id, Some(2));
        assert_eq!(forensic.filesystem.filesystem, ForensicFilesystem::ExFat);
    }

    #[test]
    fn deleted_file_maps_to_deleted() {
        let entry = entry(
            3,
            2,
            "apagado.txt",
            ExFatEntryKind::File,
            true,
            512,
            50,
            vec![50],
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.status, ForensicStatus::Deleted);
        assert_eq!(forensic.allocation.allocated, Some(false));
        assert_eq!(forensic.allocation.cluster_count, Some(1));
    }

    #[test]
    fn system_entry_maps_to_system() {
        let entry = entry(
            4,
            2,
            "Allocation Bitmap",
            ExFatEntryKind::AllocationBitmap,
            false,
            0,
            2,
            vec![2],
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.kind, ForensicEntryKind::Other);
        assert_eq!(forensic.identity.status, ForensicStatus::System);
    }

    #[test]
    fn volume_label_maps_to_system() {
        let label = ExFatInvestigationEntry::new(
            5,
            2,
            "EVID008".to_string(),
            ExFatEntryKind::VolumeLabel,
            false,
            0,
            0,
            0,
            Vec::new(),
            None,
            None,
            None,
        );

        let forensic = to_forensic(&label);

        assert_eq!(forensic.identity.kind, ForensicEntryKind::Other);
        assert_eq!(forensic.identity.status, ForensicStatus::System);
    }

    #[test]
    fn unallocated_live_file_is_inconsistent() {
        let entry = entry(
            6,
            2,
            "corrompido.bin",
            ExFatEntryKind::File,
            false,
            4096,
            0,
            vec![],
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.status, ForensicStatus::Inconsistent);
    }

    #[test]
    fn contiguous_chain_maps_to_one_region() {
        let entry = entry(
            7,
            2,
            "contiguo.bin",
            ExFatEntryKind::File,
            false,
            8192,
            10,
            vec![10, 11],
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.physical_location.regions.len(), 1);

        let region = &forensic.physical_location.regions[0];

        assert_eq!(region.cluster_start, Some(10));
        assert_eq!(region.cluster_end, Some(11));

        let sector_start = FIRST_DATA_SECTOR + 8 * 8;
        let sector_end = FIRST_DATA_SECTOR + 9 * 8 + 7;

        assert_eq!(region.sector_start, Some(sector_start));
        assert_eq!(region.sector_end, Some(sector_end));
        assert_eq!(region.offset, None);
    }

    #[test]
    fn fragmented_chain_maps_to_multiple_regions() {
        let entry = entry(
            8,
            2,
            "fragmentado.bin",
            ExFatEntryKind::File,
            false,
            16384,
            20,
            vec![20, 21, 99, 100],
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.physical_location.regions.len(), 2);

        assert_eq!(forensic.content_layout.bytes_per_cluster(), CLUSTER_SIZE);
        assert_eq!(forensic.content_layout.segment_count(), 2);

        let first = &forensic.content_layout.segments[0];
        let second = &forensic.content_layout.segments[1];

        assert_eq!(first.logical_cluster_start, 0);
        assert_eq!(first.cluster_count, 2);
        assert_eq!(second.logical_cluster_start, 2);
        assert!(matches!(second.source, ForensicContentSource::Physical(_)));
    }

    #[test]
    fn empty_chain_has_no_regions() {
        let entry = entry(9, 2, "vazio.txt", ExFatEntryKind::File, false, 0, 0, vec![]);

        let forensic = to_forensic(&entry);

        assert!(forensic.physical_location.regions.is_empty());
        assert_eq!(forensic.content_layout.segment_count(), 0);
        assert_eq!(forensic.metadata.real_size, Some(0));
    }

    #[test]
    fn timestamps_are_exposed_in_metadata() {
        let stamp = DateTime::<Utc>::from_timestamp(1767323046, 0).unwrap();

        let entry = ExFatInvestigationEntry::new(
            10,
            2,
            "datado.txt".to_string(),
            ExFatEntryKind::File,
            false,
            512,
            0x20,
            5,
            vec![5],
            Some(stamp),
            Some(stamp),
            None,
        );

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.metadata.created_at, Some(stamp));
        assert_eq!(forensic.metadata.modified_at, Some(stamp));
        assert_eq!(forensic.metadata.accessed_at, None);
    }
}

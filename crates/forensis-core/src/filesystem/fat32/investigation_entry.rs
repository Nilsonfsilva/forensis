//! FAT32 investigation entry and forensic model mapping.
//!
//! A FAT32 object is described by its directory entry (name, size,
//! attributes, first cluster) plus the FAT chain that maps the
//! logical clusters to the physical data region. This module converts
//! that representation into the filesystem-independent forensic model.

use crate::forensic::{
    ForensicAllocation, ForensicContentLayout, ForensicContentSegment, ForensicEntry,
    ForensicEntryKind, ForensicFilesystem, ForensicHierarchy, ForensicIdentity, ForensicMetadata,
    ForensicObject, ForensicPhysicalLocation, ForensicPhysicalRegion, ForensicStatus,
};

/// Represents an item discovered during a FAT32 investigation.
///
/// This structure belongs exclusively to the FAT32 layer. The
/// filesystem-independent forensic model is obtained exclusively
/// through `to_forensic_entry()`.
#[derive(Debug, Clone)]
pub struct Fat32InvestigationEntry {
    object_id: u64,
    parent_id: u64,
    name: String,
    is_directory: bool,
    is_volume_label: bool,
    deleted: bool,
    real_size: u64,
    attributes: u8,
    cluster: u32,
    chain: Vec<u32>,
}

impl Fat32InvestigationEntry {
    /// Creates a FAT32 investigation entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        object_id: u64,
        parent_id: u64,
        name: String,
        is_directory: bool,
        is_volume_label: bool,
        deleted: bool,
        real_size: u64,
        attributes: u8,
        cluster: u32,
        chain: Vec<u32>,
    ) -> Self {
        Self {
            object_id,
            parent_id,
            name,
            is_directory,
            is_volume_label,
            deleted,
            real_size,
            attributes,
            cluster,
            chain,
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

    /// Returns true when the entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Returns true when the entry is the volume label.
    pub fn is_volume_label(&self) -> bool {
        self.is_volume_label
    }

    /// Returns true when the entry has been deleted.
    pub fn deleted(&self) -> bool {
        self.deleted
    }

    /// Returns the file size recorded in the directory entry.
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

    /// Returns true when the entry has no valid data allocation.
    fn is_unallocated(&self) -> bool {
        self.chain.is_empty()
    }

    /// Merges consecutive chain clusters into physical regions.
    ///
    /// Sectors are partition-relative, following the convention used
    /// by the recovery engine. The `first_data_sector` value keeps the
    /// sector mapping consistent with the geometry parsed from the
    /// boot sector.
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
    ///
    /// The logical position is expressed in clusters. FAT32 has no file
    /// holes: every chain cluster stores real data. Empty chains map to
    /// an empty layout.
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

    /// Converts the FAT32-specific entry into the forensic model.
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
        let kind = if self.is_volume_label {
            ForensicEntryKind::Other
        } else if self.is_directory {
            ForensicEntryKind::Directory
        } else {
            ForensicEntryKind::File
        };

        let status = if self.deleted {
            ForensicStatus::Deleted
        } else if self.is_volume_label {
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
        );

        let filesystem_object = ForensicObject::new(ForensicFilesystem::Fat32, self.cluster as u64);

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
    const FIRST_DATA_SECTOR: u64 = 1056;

    #[allow(clippy::too_many_arguments)]
    fn entry(
        object_id: u64,
        parent: u64,
        name: &str,
        is_directory: bool,
        deleted: bool,
        real_size: u64,
        cluster: u32,
        chain: Vec<u32>,
    ) -> Fat32InvestigationEntry {
        Fat32InvestigationEntry::new(
            object_id,
            parent,
            name.to_string(),
            is_directory,
            false,
            deleted,
            real_size,
            0x20,
            cluster,
            chain,
        )
    }

    fn to_forensic(entry: &Fat32InvestigationEntry) -> ForensicEntry {
        entry.to_forensic_entry(CLUSTER_SIZE, SECTORS_PER_CLUSTER, FIRST_DATA_SECTOR)
    }

    #[test]
    fn regular_file_maps_to_normal() {
        let entry = entry(1, 2, "relatorio.txt", false, false, 8192, 42, vec![42, 43]);

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.name, "relatorio.txt");
        assert_eq!(forensic.identity.kind, ForensicEntryKind::File);
        assert_eq!(forensic.identity.status, ForensicStatus::Normal);
        assert_eq!(forensic.identity.object_id, 1);
        assert_eq!(forensic.hierarchy.parent_id, Some(2));
        assert_eq!(forensic.filesystem.filesystem, ForensicFilesystem::Fat32);
    }

    #[test]
    fn deleted_file_maps_to_deleted() {
        let entry = entry(3, 2, "apagado.txt", false, true, 512, 50, vec![50]);

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.status, ForensicStatus::Deleted);
        assert_eq!(forensic.allocation.allocated, Some(false));
        assert_eq!(forensic.allocation.cluster_count, Some(1));
    }

    #[test]
    fn volume_label_is_system_other() {
        let label = Fat32InvestigationEntry::new(
            4,
            2,
            "EVIDENCIA1".to_string(),
            false,
            true,
            false,
            0,
            0x08,
            0,
            vec![],
        );

        let forensic = to_forensic(&label);

        assert_eq!(forensic.identity.kind, ForensicEntryKind::Other);
        assert_eq!(forensic.identity.status, ForensicStatus::System);
    }

    #[test]
    fn unallocated_live_file_is_inconsistent() {
        let entry = entry(5, 2, "corrompido.bin", false, false, 4096, 0, vec![]);

        let forensic = to_forensic(&entry);

        assert_eq!(forensic.identity.status, ForensicStatus::Inconsistent);
    }

    #[test]
    fn contiguous_chain_maps_to_one_region() {
        let entry = entry(6, 2, "contiguo.bin", false, false, 8192, 10, vec![10, 11]);

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
            7,
            2,
            "fragmentado.bin",
            false,
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
        let entry = entry(8, 2, "vazio.txt", false, false, 0, 0, vec![]);

        let forensic = to_forensic(&entry);

        assert!(forensic.physical_location.regions.is_empty());
        assert_eq!(forensic.content_layout.segment_count(), 0);
        assert_eq!(forensic.metadata.real_size, Some(0));
    }
}

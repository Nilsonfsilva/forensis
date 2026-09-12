use super::extent::Ext4Extent;

use crate::forensic::{
    ForensicAllocation, ForensicContentLayout, ForensicContentSegment, ForensicEntry,
    ForensicEntryKind, ForensicFilesystem, ForensicHierarchy, ForensicIdentity, ForensicMetadata,
    ForensicObject, ForensicPhysicalLocation, ForensicPhysicalRegion, ForensicStatus,
};

/// EXT4 inode file type mask.
const EXT4_FILE_TYPE_MASK: u16 = 0xF000;

/// EXT4 symbolic link file type.
const EXT4_SYMLINK_TYPE: u16 = 0xA000;

/// Reserved EXT4 system inodes.
///
/// Inode 1 is the bad-block inode. Inodes 3 through 10 are
/// reserved for internal EXT4 use. The root directory (inode 2)
/// is a real user directory and is therefore not included.
fn is_ext4_system_inode(inode_number: u32) -> bool {
    inode_number == 1 || (3..=10).contains(&inode_number)
}

/// Represents an item discovered during the EXT4 investigation.
///
/// This structure belongs exclusively to the EXT4 layer.
///
/// It may know about inodes, extent trees, directory entries
/// and EXT4 metadata. The filesystem-independent forensic model
/// is obtained exclusively through `to_forensic_entry()`.
#[derive(Debug, Clone)]
pub struct Ext4InvestigationEntry {
    inode_number: u32,
    parent_inode: u32,
    name: String,
    is_directory: bool,
    real_size: u64,
    allocated_size: u64,
    mode: u16,
    flags: u32,
    dtime: u32,
    links_count: u16,
    extents: Vec<Ext4Extent>,
    data: Option<Vec<u8>>,
    bitmap_allocated: bool,
}

impl Ext4InvestigationEntry {
    /// Creates an EXT4 investigation entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inode_number: u32,
        parent_inode: u32,
        name: String,
        is_directory: bool,
        real_size: u64,
        allocated_size: u64,
        mode: u16,
        flags: u32,
        dtime: u32,
        links_count: u16,
        extents: Vec<Ext4Extent>,
        data: Option<Vec<u8>>,
        bitmap_allocated: bool,
    ) -> Self {
        Self {
            inode_number,
            parent_inode,
            name,
            is_directory,
            real_size,
            allocated_size,
            mode,
            flags,
            dtime,
            links_count,
            extents,
            data,
            bitmap_allocated,
        }
    }

    /// Returns the inode number.
    pub fn inode_number(&self) -> u32 {
        self.inode_number
    }

    /// Returns the parent directory inode number.
    pub fn parent_inode(&self) -> u32 {
        self.parent_inode
    }

    /// Returns the file or directory name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns true when the entry represents a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Returns the real file size.
    pub fn real_size(&self) -> u64 {
        self.real_size
    }

    /// Returns the allocated size on disk.
    pub fn allocated_size(&self) -> u64 {
        self.allocated_size
    }

    /// Returns the EXT4 inode mode.
    pub fn mode(&self) -> u16 {
        self.mode
    }

    /// Returns the EXT4 inode flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the deletion timestamp.
    ///
    /// A value of zero means the inode was not deleted.
    pub fn dtime(&self) -> u32 {
        self.dtime
    }

    /// Returns the hard link count.
    pub fn links_count(&self) -> u16 {
        self.links_count
    }

    /// Returns the extents describing the file allocation.
    pub fn extents(&self) -> &[Ext4Extent] {
        &self.extents
    }

    /// Returns inline content, when the entry stores its bytes
    /// directly inside the inode (fast symbolic links).
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Returns true when the inode bitmap marks this inode
    /// as currently allocated.
    pub fn bitmap_allocated(&self) -> bool {
        self.bitmap_allocated
    }

    /// Returns true when the inode is deleted.
    ///
    /// EXT4 sets the deletion timestamp and clears the link
    /// count when a file is removed.
    fn is_deleted(&self) -> bool {
        self.dtime != 0 || self.links_count == 0
    }

    /// Returns true when the inode has no physical allocation.
    fn is_unallocated(&self) -> bool {
        self.extents.is_empty() && self.data.is_none()
    }

    /// Converts the extents into physical forensic regions.
    ///
    /// Physical region sectors are expressed relative to the
    /// beginning of the filesystem partition, following the
    /// convention used by the recovery engine.
    ///
    /// `sectors_per_block` is the number of 512-byte sectors
    /// contained in one filesystem block.
    fn physical_location(&self, sectors_per_block: u64) -> ForensicPhysicalLocation {
        let mut location = ForensicPhysicalLocation::empty();

        if sectors_per_block == 0 {
            return location;
        }

        for extent in &self.extents {
            if let Some(region) = self.physical_region_for_extent(extent, sectors_per_block) {
                location.add_region(region);
            }
        }

        location
    }

    /// Converts one non-sparse extent into a physical
    /// forensic region.
    ///
    /// The logical cluster values refer to the filesystem
    /// physical blocks, while the sector values refer to the
    /// partition-relative sector range.
    fn physical_region_for_extent(
        &self,
        extent: &Ext4Extent,
        sectors_per_block: u64,
    ) -> Option<ForensicPhysicalRegion> {
        if !extent.is_initialized() || extent.length() == 0 {
            return None;
        }

        let cluster_start = extent.physical_block();
        let cluster_end = extent.last_physical_block();

        let sector_start = cluster_start.checked_mul(sectors_per_block)?;

        let sector_end = cluster_end
            .checked_mul(sectors_per_block)?
            .checked_add(sectors_per_block.saturating_sub(1))?;

        Some(ForensicPhysicalRegion::from_ranges(
            cluster_start,
            cluster_end,
            sector_start,
            sector_end,
            None,
        ))
    }

    /// Converts the extent list into the logical content
    /// sequence consumed by the generic forensic model.
    ///
    /// The logical position is expressed in filesystem blocks.
    ///
    /// Uninitialized extents and logical gaps between extents
    /// (file holes) are represented as sparse segments, exactly
    /// as NTFS sparse runs are handled by the common model.
    fn content_layout(
        &self,
        bytes_per_block: u64,
        sectors_per_block: u64,
    ) -> ForensicContentLayout {
        if bytes_per_block == 0 || sectors_per_block == 0 {
            return ForensicContentLayout::empty();
        }

        /*
         * Inline content (fast symbolic links) is already present
         * in memory as the exact logical bytes and must not be
         * expanded to a full filesystem block.
         */
        if let Some(data) = &self.data {
            return ForensicContentLayout::new(
                bytes_per_block,
                vec![ForensicContentSegment::inline(
                    0,
                    data.clone(),
                    bytes_per_block,
                )],
            );
        }

        let mut segments = Vec::new();

        let mut logical_cluster_start = 0u64;

        for extent in &self.extents {
            if extent.length() == 0 {
                continue;
            }

            let extent_start = extent.logical_block() as u64;

            if extent_start > logical_cluster_start {
                let gap = extent_start - logical_cluster_start;

                segments.push(ForensicContentSegment::sparse(logical_cluster_start, gap));

                logical_cluster_start = extent_start;
            }

            let physical_region = self.physical_region_for_extent(extent, sectors_per_block);

            let segment = match physical_region {
                Some(region) => ForensicContentSegment::physical(
                    logical_cluster_start,
                    extent.length() as u64,
                    region,
                ),
                None => {
                    ForensicContentSegment::sparse(logical_cluster_start, extent.length() as u64)
                }
            };

            segments.push(segment);

            logical_cluster_start += extent.length() as u64;
        }

        ForensicContentLayout::new(bytes_per_block, segments)
    }

    /// Converts the EXT4-specific investigation entry into
    /// the filesystem-independent forensic model.
    pub fn to_forensic_entry(&self, bytes_per_block: u64, sectors_per_block: u64) -> ForensicEntry {
        let is_root = self.is_directory && self.inode_number == self.parent_inode;

        let kind = if self.is_directory {
            ForensicEntryKind::Directory
        } else if self.mode & EXT4_FILE_TYPE_MASK == EXT4_SYMLINK_TYPE {
            ForensicEntryKind::Symlink
        } else {
            ForensicEntryKind::File
        };

        let status = if self.is_deleted() {
            ForensicStatus::Deleted
        } else if is_ext4_system_inode(self.inode_number) {
            ForensicStatus::System
        } else if !self.is_directory && self.real_size > 0 && self.is_unallocated() {
            ForensicStatus::Inconsistent
        } else {
            ForensicStatus::Normal
        };

        let name = if is_root {
            "/".to_string()
        } else {
            self.name.clone()
        };

        let identity =
            ForensicIdentity::new(name, String::new(), kind, status, self.inode_number as u64);

        let hierarchy = ForensicHierarchy::new(Some(self.parent_inode as u64));

        let metadata = ForensicMetadata::new(Some(self.real_size), Some(self.allocated_size));

        let filesystem_object =
            ForensicObject::new(ForensicFilesystem::Ext4, self.inode_number as u64);

        let cluster_count = if self.extents.is_empty() {
            None
        } else {
            Some(
                self.extents
                    .iter()
                    .map(|extent| extent.length() as u64)
                    .sum(),
            )
        };

        let allocation = ForensicAllocation {
            allocated: Some(!self.is_deleted()),
            cluster_count,
            bitmap_allocated: Some(self.bitmap_allocated),
        };

        let physical_location = self.physical_location(sectors_per_block);

        let content_layout = self.content_layout(bytes_per_block, sectors_per_block);

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
    use crate::forensic::{ForensicEntryKind, ForensicStatus};

    const BLOCK_SIZE: u64 = 4096;
    const SECTORS_PER_BLOCK: u64 = 8;

    fn extent(logical: u32, physical: u64, length: u16, initialized: bool) -> Ext4Extent {
        let mut raw = [0u8; 12];

        raw[0..4].copy_from_slice(&logical.to_le_bytes());

        let length_field = if initialized { length } else { length | 0x8000 };

        raw[4..6].copy_from_slice(&length_field.to_le_bytes());

        raw[6..8].copy_from_slice(&((physical >> 32) as u16).to_le_bytes());

        raw[8..12].copy_from_slice(&(physical as u32).to_le_bytes());

        Ext4Extent::parse(&raw).unwrap()
    }

    fn entry(
        inode_number: u32,
        parent_inode: u32,
        name: &str,
        is_directory: bool,
        real_size: u64,
        extents: Vec<Ext4Extent>,
    ) -> Ext4InvestigationEntry {
        Ext4InvestigationEntry::new(
            inode_number,
            parent_inode,
            name.to_string(),
            is_directory,
            real_size,
            extents
                .iter()
                .map(|extent| extent.length() as u64 * BLOCK_SIZE)
                .sum(),
            0x81A4,
            0,
            0,
            1,
            extents,
            None,
            true,
        )
    }

    #[test]
    fn regular_file_maps_to_normal() {
        let entry = entry(
            42,
            2,
            "arquivo.txt",
            false,
            8192,
            vec![extent(0, 100, 2, true)],
        );

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert_eq!(forensic.identity.name, "arquivo.txt");
        assert_eq!(forensic.identity.kind, ForensicEntryKind::File);
        assert_eq!(forensic.identity.status, ForensicStatus::Normal);
        assert_eq!(forensic.identity.object_id, 42);
        assert_eq!(forensic.hierarchy.parent_id, Some(2));
        assert_eq!(forensic.filesystem.filesystem, ForensicFilesystem::Ext4);
    }

    #[test]
    fn root_directory_gets_slash_name() {
        let entry = entry(2, 2, "", true, 4096, vec![extent(0, 100, 1, true)]);

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert_eq!(forensic.identity.name, "/");
        assert_eq!(forensic.identity.kind, ForensicEntryKind::Directory);
        assert_eq!(forensic.identity.status, ForensicStatus::Normal);
    }

    #[test]
    fn reserved_inode_is_system() {
        let entry = entry(1, 2, "bad-blocks", false, 0, vec![]);

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert_eq!(forensic.identity.status, ForensicStatus::System);
    }

    #[test]
    fn deleted_inode_maps_to_deleted() {
        let deleted = Ext4InvestigationEntry::new(
            77,
            2,
            "apagado.txt".to_string(),
            false,
            512,
            4096,
            0x81A4,
            0,
            1234567890,
            0,
            vec![extent(0, 500, 1, true)],
            None,
            true,
        );

        let forensic = deleted.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert_eq!(forensic.identity.status, ForensicStatus::Deleted);
        assert_eq!(forensic.allocation.allocated, Some(false));
        assert_eq!(forensic.allocation.bitmap_allocated, Some(true));
    }

    #[test]
    fn unallocated_live_file_is_inconsistent() {
        let entry = entry(50, 2, "corrupto.bin", false, 4096, vec![]);

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert_eq!(forensic.identity.status, ForensicStatus::Inconsistent);
    }

    #[test]
    fn physical_extent_maps_to_partition_relative_sectors() {
        let entry = entry(5, 2, "dados.bin", false, 4096, vec![extent(0, 10, 1, true)]);

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        let region = &forensic.physical_location.regions[0];

        assert_eq!(region.cluster_start, Some(10));
        assert_eq!(region.cluster_end, Some(10));
        assert_eq!(region.sector_start, Some(80));
        assert_eq!(region.sector_end, Some(87));
        assert_eq!(region.offset, None);
    }

    #[test]
    fn uninitialized_extent_becomes_sparse() {
        let entry = entry(
            6,
            2,
            "sparse.bin",
            false,
            8192,
            vec![extent(0, 20, 1, false)],
        );

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert!(forensic.physical_location.regions.is_empty());

        assert_eq!(forensic.content_layout.bytes_per_cluster(), BLOCK_SIZE);

        let segment = &forensic.content_layout.segments[0];

        assert!(matches!(segment.source, ForensicContentSource::Sparse));
    }

    #[test]
    fn holes_between_extents_are_sparse() {
        let entry = entry(
            7,
            2,
            "fragmentado.bin",
            false,
            16384,
            vec![extent(0, 30, 1, true), extent(4, 40, 1, true)],
        );

        let forensic = entry.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        let segments = &forensic.content_layout.segments;

        assert_eq!(segments.len(), 3);

        assert!(matches!(
            segments[0].source,
            ForensicContentSource::Physical(_)
        ));
        assert_eq!(segments[0].cluster_count, 1);

        assert!(matches!(segments[1].source, ForensicContentSource::Sparse));
        assert_eq!(segments[1].logical_cluster_start, 1);
        assert_eq!(segments[1].cluster_count, 3);

        assert!(matches!(
            segments[2].source,
            ForensicContentSource::Physical(_)
        ));
        assert_eq!(segments[2].logical_cluster_start, 4);
    }

    #[test]
    fn fast_symlink_is_inline() {
        let symlink = Ext4InvestigationEntry::new(
            8,
            2,
            "link".to_string(),
            false,
            5,
            0,
            0xA1FF,
            0,
            0,
            1,
            vec![],
            Some(b"target".to_vec()),
            true,
        );

        let forensic = symlink.to_forensic_entry(BLOCK_SIZE, SECTORS_PER_BLOCK);

        assert_eq!(forensic.identity.kind, ForensicEntryKind::Symlink);

        let segment = &forensic.content_layout.segments[0];

        assert!(matches!(
            &segment.source,
            ForensicContentSource::Inline(data) if data == b"target"
        ));
    }
}

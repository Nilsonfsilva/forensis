/// Consolidated forensic model used by Forensis.
///
/// This is the final representation of evidence produced
/// by filesystem parsers.
///
/// The application and interfaces do not need to know
/// NTFS, MFT, inode, DATA, FILE_NAME or any other
/// filesystem-specific structure.
///
/// Parsers produce the data.
/// The model consolidates it.
/// The application consumes the model.
///
/// The structure is designed to remain independent
/// of the investigated filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicModel {
    source: ForensicSource,
    records_investigated: u64,
    entries: Vec<ForensicEntry>,
}

impl ForensicModel {
    /// Creates a new consolidated forensic model.
    pub fn new(
        source: ForensicSource,
        records_investigated: u64,
        entries: Vec<ForensicEntry>,
    ) -> Self {
        Self {
            source,
            records_investigated,
            entries,
        }
    }

    /// Returns the evidence source.
    pub fn source(&self) -> &ForensicSource {
        &self.source
    }

    /// Returns the number of investigated records.
    ///
    /// For NTFS, this corresponds to the number of
    /// MFT records actually processed.
    pub fn records_investigated(&self) -> u64 {
        self.records_investigated
    }

    /// Returns all discovered entries.
    pub fn entries(&self) -> &[ForensicEntry] {
        &self.entries
    }

    /// Returns an entry by object identifier.
    pub fn entry(&self, object_id: u64) -> Option<&ForensicEntry> {
        self.entries
            .iter()
            .find(|entry| entry.identity.object_id == object_id)
    }

    /// Returns all entries belonging to a given parent object.
    pub fn children_of(&self, parent_id: u64) -> Vec<&ForensicEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.hierarchy.parent_id == Some(parent_id))
            .collect()
    }

    /// Returns the number of discovered entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when the model contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Source of the investigated evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicSource {
    image: Option<String>,
    filesystem: ForensicFilesystem,
}

impl ForensicSource {
    /// Creates a new evidence source.
    pub fn new(image: Option<String>, filesystem: ForensicFilesystem) -> Self {
        Self { image, filesystem }
    }

    /// Returns the image path when known.
    pub fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }

    /// Returns the investigated filesystem.
    pub fn filesystem(&self) -> ForensicFilesystem {
        self.filesystem
    }
}

/// Represents one individual forensic finding.
///
/// This is the structure consumed by the application
/// to represent a file, directory or other discovered object.
///
/// The information is organized according to forensic meaning,
/// rather than according to the internal structure of a filesystem parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicEntry {
    pub identity: ForensicIdentity,
    pub hierarchy: ForensicHierarchy,
    pub metadata: ForensicMetadata,
    pub filesystem: ForensicObject,
    pub allocation: ForensicAllocation,

    /// Physical regions that actually exist on the image.
    ///
    /// Sparse portions are deliberately not represented here
    /// because they do not correspond to physical disk regions.
    pub physical_location: ForensicPhysicalLocation,

    /// Logical order of the object's content.
    ///
    /// This representation is used during recovery so that
    /// fragmented and sparse content can be reconstructed
    /// in its original logical order.
    pub content_layout: ForensicContentLayout,
}

impl ForensicEntry {
    pub fn new(
        identity: ForensicIdentity,
        hierarchy: ForensicHierarchy,
        metadata: ForensicMetadata,
        filesystem: ForensicObject,
        allocation: ForensicAllocation,
        physical_location: ForensicPhysicalLocation,
    ) -> Self {
        Self {
            identity,
            hierarchy,
            metadata,
            filesystem,
            allocation,
            physical_location,
            content_layout: ForensicContentLayout::empty(),
        }
    }

    /// Associates a logical content layout with the entry.
    pub fn with_content_layout(mut self, content_layout: ForensicContentLayout) -> Self {
        self.content_layout = content_layout;
        self
    }

    pub fn is_file(&self) -> bool {
        self.identity.kind == ForensicEntryKind::File
    }

    pub fn is_directory(&self) -> bool {
        self.identity.kind == ForensicEntryKind::Directory
    }

    pub fn is_deleted(&self) -> bool {
        self.identity.status == ForensicStatus::Deleted
    }

    pub fn is_carved(&self) -> bool {
        self.identity.status == ForensicStatus::Carved
    }

    pub fn is_system(&self) -> bool {
        self.identity.status == ForensicStatus::System
    }

    pub fn is_inconsistent(&self) -> bool {
        self.identity.status == ForensicStatus::Inconsistent
    }
}

/// Logical content layout of a forensic object.
///
/// The layout describes how the object's bytes are ordered
/// from the logical beginning of the file to the logical end.
///
/// `bytes_per_cluster` describes the logical allocation unit.
/// It is metadata supplied by the filesystem parser and does
/// not make this structure filesystem-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicContentLayout {
    pub bytes_per_cluster: u64,
    pub segments: Vec<ForensicContentSegment>,
}

impl ForensicContentLayout {
    /// Creates an empty content layout.
    pub fn empty() -> Self {
        Self {
            bytes_per_cluster: 0,
            segments: Vec::new(),
        }
    }

    /// Creates a content layout.
    pub fn new(bytes_per_cluster: u64, segments: Vec<ForensicContentSegment>) -> Self {
        Self {
            bytes_per_cluster,
            segments,
        }
    }

    /// Returns the bytes represented by one logical cluster.
    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_cluster
    }

    /// Returns all logical content segments.
    pub fn segments(&self) -> &[ForensicContentSegment] {
        &self.segments
    }

    /// Returns the number of logical content segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns true when no logical content layout exists.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// Source of the bytes represented by one logical content segment.
///
/// `Physical` means that the bytes must be read from the
/// investigated image.
///
/// `Sparse` means that the logical bytes have no physical
/// storage and therefore must be reconstructed as zeros.
///
/// `Inline` means that the bytes are already present in the
/// filesystem metadata and do not need a physical image read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForensicContentSource {
    Physical(ForensicPhysicalRegion),
    Sparse,
    Inline(Vec<u8>),
}

/// One logical segment of an object's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicContentSegment {
    /// Logical position expressed in clusters.
    pub logical_cluster_start: u64,

    /// Number of logical clusters represented by this segment.
    ///
    /// For physical and sparse segments this represents the
    /// logical allocation extent.
    ///
    /// For inline segments this value represents the logical
    /// cluster span required to contain the inline bytes.
    pub cluster_count: u64,

    /// Source containing the bytes represented by this segment.
    pub source: ForensicContentSource,
}

impl ForensicContentSegment {
    /// Creates a physical logical-content segment.
    pub fn physical(
        logical_cluster_start: u64,
        cluster_count: u64,
        physical_region: ForensicPhysicalRegion,
    ) -> Self {
        Self {
            logical_cluster_start,
            cluster_count,
            source: ForensicContentSource::Physical(physical_region),
        }
    }

    /// Creates a sparse logical-content segment.
    pub fn sparse(logical_cluster_start: u64, cluster_count: u64) -> Self {
        Self {
            logical_cluster_start,
            cluster_count,
            source: ForensicContentSource::Sparse,
        }
    }

    /// Creates an inline logical-content segment.
    pub fn inline(logical_cluster_start: u64, data: Vec<u8>, bytes_per_cluster: u64) -> Self {
        let cluster_count = if data.is_empty() || bytes_per_cluster == 0 {
            0
        } else {
            data.len().div_ceil(bytes_per_cluster as usize) as u64
        };

        Self {
            logical_cluster_start,
            cluster_count,
            source: ForensicContentSource::Inline(data),
        }
    }

    /// Returns the physical region backing this segment, when present.
    pub fn physical_region(&self) -> Option<&ForensicPhysicalRegion> {
        match &self.source {
            ForensicContentSource::Physical(region) => Some(region),
            ForensicContentSource::Sparse | ForensicContentSource::Inline(_) => None,
        }
    }

    /// Returns the inline bytes backing this segment, when present.
    pub fn inline_data(&self) -> Option<&[u8]> {
        match &self.source {
            ForensicContentSource::Inline(data) => Some(data),
            ForensicContentSource::Physical(_) | ForensicContentSource::Sparse => None,
        }
    }

    /// Returns true when the segment represents sparse content.
    pub fn is_sparse(&self) -> bool {
        matches!(self.source, ForensicContentSource::Sparse)
    }

    /// Returns true when the segment contains inline content.
    pub fn is_inline(&self) -> bool {
        matches!(self.source, ForensicContentSource::Inline(_))
    }

    /// Returns the number of bytes represented by this segment.
    ///
    /// Inline content has an exact byte length because its data
    /// is already available in memory.
    ///
    /// Physical and sparse content are represented in logical
    /// clusters and therefore use the supplied cluster size.
    pub fn byte_count(&self, bytes_per_cluster: u64) -> Option<u64> {
        match &self.source {
            ForensicContentSource::Inline(data) => Some(data.len() as u64),

            ForensicContentSource::Physical(_) | ForensicContentSource::Sparse => {
                self.cluster_count.checked_mul(bytes_per_cluster)
            }
        }
    }
}

/// Identity presented to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicIdentity {
    pub name: String,
    pub path: String,
    pub kind: ForensicEntryKind,
    pub status: ForensicStatus,
    pub object_id: u64,
}

impl ForensicIdentity {
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        kind: ForensicEntryKind,
        status: ForensicStatus,
        object_id: u64,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            kind,
            status,
            object_id,
        }
    }
}

/// Hierarchical relationship of the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicHierarchy {
    pub parent_id: Option<u64>,
}

impl ForensicHierarchy {
    pub fn new(parent_id: Option<u64>) -> Self {
        Self { parent_id }
    }
}

/// Generic metadata associated with the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicMetadata {
    pub real_size: Option<u64>,
    pub allocated_size: Option<u64>,

    /// Creation timestamp of the object when the filesystem records it.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Last modification timestamp of the object when recorded.
    pub modified_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Last access timestamp of the object when recorded.
    pub accessed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ForensicMetadata {
    pub fn new(real_size: Option<u64>, allocated_size: Option<u64>) -> Self {
        Self {
            real_size,
            allocated_size,
            created_at: None,
            modified_at: None,
            accessed_at: None,
        }
    }

    /// Associates filesystem timestamps with the metadata.
    pub fn with_timestamps(
        mut self,
        created_at: Option<chrono::DateTime<chrono::Utc>>,
        modified_at: Option<chrono::DateTime<chrono::Utc>>,
        accessed_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        self.created_at = created_at;
        self.modified_at = modified_at;
        self.accessed_at = accessed_at;
        self
    }
}

/// Filesystem-specific object identity.
///
/// The model only knows the generic concept of a filesystem object.
/// The filesystem parser remains responsible for interpreting
/// MFT records, inodes and other filesystem structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicObject {
    pub filesystem: ForensicFilesystem,
    pub filesystem_object_id: u64,
}

impl ForensicObject {
    pub fn new(filesystem: ForensicFilesystem, filesystem_object_id: u64) -> Self {
        Self {
            filesystem,
            filesystem_object_id,
        }
    }
}

/// Allocation information associated with the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicAllocation {
    pub allocated: Option<bool>,
    pub cluster_count: Option<u64>,
    pub bitmap_allocated: Option<bool>,
}

impl ForensicAllocation {
    pub fn empty() -> Self {
        Self {
            allocated: None,
            cluster_count: None,
            bitmap_allocated: None,
        }
    }
}

/// Physical location of one forensic data region.
///
/// A file may occupy multiple non-contiguous physical regions.
/// Each region is represented independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicPhysicalRegion {
    /// First logical cluster number of the region.
    pub cluster_start: Option<u64>,

    /// Last logical cluster number of the region.
    pub cluster_end: Option<u64>,

    /// First physical sector occupied by the region.
    pub sector_start: Option<u64>,

    /// Last physical sector occupied by the region.
    pub sector_end: Option<u64>,

    /// Byte offset of the region when known.
    pub offset: Option<u64>,
}

impl ForensicPhysicalRegion {
    /// Creates an empty physical region.
    pub fn empty() -> Self {
        Self {
            cluster_start: None,
            cluster_end: None,
            sector_start: None,
            sector_end: None,
            offset: None,
        }
    }

    /// Creates a physical region from a cluster range.
    pub fn from_clusters(cluster_start: u64, cluster_end: u64) -> Self {
        Self {
            cluster_start: Some(cluster_start),
            cluster_end: Some(cluster_end),
            sector_start: None,
            sector_end: None,
            offset: None,
        }
    }

    /// Creates a physical region from a cluster range
    /// and a sector range.
    pub fn from_ranges(
        cluster_start: u64,
        cluster_end: u64,
        sector_start: u64,
        sector_end: u64,
        offset: Option<u64>,
    ) -> Self {
        Self {
            cluster_start: Some(cluster_start),
            cluster_end: Some(cluster_end),
            sector_start: Some(sector_start),
            sector_end: Some(sector_end),
            offset,
        }
    }

    /// Returns the number of clusters represented by the region.
    pub fn cluster_count(&self) -> Option<u64> {
        match (self.cluster_start, self.cluster_end) {
            (Some(start), Some(end)) if end >= start => Some(end - start + 1),
            _ => None,
        }
    }

    /// Returns the number of sectors represented by the region.
    pub fn sector_count(&self) -> Option<u64> {
        match (self.sector_start, self.sector_end) {
            (Some(start), Some(end)) if end >= start => Some(end - start + 1),
            _ => None,
        }
    }
}

/// Physical allocation information of a forensic object.
///
/// The object may contain multiple physical regions because
/// filesystem allocation can be fragmented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicPhysicalLocation {
    pub regions: Vec<ForensicPhysicalRegion>,
}

impl ForensicPhysicalLocation {
    /// Creates an empty physical location.
    pub fn empty() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Creates a physical location containing one region.
    pub fn from_region(region: ForensicPhysicalRegion) -> Self {
        Self {
            regions: vec![region],
        }
    }

    /// Adds one physical region.
    pub fn add_region(&mut self, region: ForensicPhysicalRegion) {
        self.regions.push(region);
    }

    /// Returns all physical regions.
    pub fn regions(&self) -> &[ForensicPhysicalRegion] {
        &self.regions
    }

    /// Returns the number of physical regions.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForensicEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForensicStatus {
    Normal,
    System,
    Deleted,
    Carved,
    Inconsistent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForensicFilesystem {
    Ntfs,
    Ext4,
    Ext3,
    Fat32,
    ExFat,
    Unknown,
}

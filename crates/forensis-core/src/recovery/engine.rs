use crate::forensic::model::ForensicContentSource;
use crate::forensic::{ForensicContentSegment, ForensicEntry, ForensicPhysicalRegion};

use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

use super::RecoveryResult;

/// Generic recovery engine.
///
/// This trait deliberately knows nothing about NTFS, EXT4,
/// FAT32, MFT records, inodes, extents or other filesystem
/// structures.
///
/// The filesystem layer produces the common `ForensicEntry`.
/// The recovery implementation consumes that representation.
pub trait RecoveryEngine {
    /// Recovers one forensic object.
    fn recover<R: Readable>(&self, reader: &mut R, entry: &ForensicEntry)
        -> Result<RecoveryResult>;
}

/// Generic recovery engine based on physical forensic regions
/// and logical content layout.
///
/// This implementation is filesystem-independent.
///
/// The engine receives a generic forensic object and reconstructs
/// its logical content from the content layout.
///
/// Physical segments are read from the image.
///
/// Sparse segments are reconstructed as zero-filled bytes.
///
/// Inline segments already contain their content in the forensic
/// model and therefore do not require an image read.
///
/// The engine does not interpret filesystem structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRecoveryEngine {
    /// Absolute byte offset where the investigated
    /// filesystem partition begins in the image.
    partition_offset: u64,

    /// Number of bytes contained in one physical sector.
    bytes_per_sector: u64,
}

impl PhysicalRecoveryEngine {
    /// Creates a physical recovery engine.
    ///
    /// `partition_offset` is the absolute byte offset of the
    /// filesystem partition inside the image.
    ///
    /// `bytes_per_sector` is the physical sector size.
    pub fn new(partition_offset: u64, bytes_per_sector: u64) -> Self {
        Self {
            partition_offset,
            bytes_per_sector,
        }
    }

    /// Returns the partition byte offset.
    pub fn partition_offset(&self) -> u64 {
        self.partition_offset
    }

    /// Returns the physical sector size.
    pub fn bytes_per_sector(&self) -> u64 {
        self.bytes_per_sector
    }

    /// Calculates the absolute byte offset of a physical sector.
    fn sector_offset(&self, sector: u64) -> Option<u64> {
        let relative_offset = sector.checked_mul(self.bytes_per_sector)?;

        self.partition_offset.checked_add(relative_offset)
    }

    /// Returns the number of bytes represented by a physical region.
    fn region_size(&self, region: &ForensicPhysicalRegion) -> Option<u64> {
        let sector_count = region.sector_count()?;

        sector_count.checked_mul(self.bytes_per_sector)
    }

    /// Returns the absolute byte offset of a physical region.
    ///
    /// An explicitly known byte offset has priority.
    ///
    /// Otherwise the offset is calculated from the physical
    /// sector range.
    fn region_offset(&self, region: &ForensicPhysicalRegion) -> Option<u64> {
        if let Some(offset) = region.offset {
            return Some(offset);
        }

        let sector_start = region.sector_start?;

        self.sector_offset(sector_start)
    }

    /// Reads one physical forensic region.
    fn read_region<R: Readable>(
        &self,
        reader: &mut R,
        region: &ForensicPhysicalRegion,
        bytes_to_read: usize,
    ) -> Result<Vec<u8>> {
        let offset = self.region_offset(region).ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat(
                "Physical forensic region has no readable offset".to_string(),
            )
        })?;

        let region_size = self.region_size(region).ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat(
                "Invalid physical forensic region size".to_string(),
            )
        })?;

        if bytes_to_read as u64 > region_size {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Requested recovery size exceeds physical region".to_string(),
            ));
        }

        let end = offset.checked_add(bytes_to_read as u64).ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat(
                "Physical recovery offset overflow".to_string(),
            )
        })?;

        if end > reader.size().value() {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Physical recovery region exceeds image size".to_string(),
            ));
        }

        let mut buffer = vec![0u8; bytes_to_read];

        if !buffer.is_empty() {
            reader.read_at(ByteOffset::new(offset), &mut buffer)?;
        }

        Ok(buffer)
    }

    /// Recovers one logical content segment.
    ///
    /// A physical segment is read from the investigated image.
    ///
    /// A sparse segment has no physical storage and is reconstructed
    /// as zero-filled logical content.
    ///
    /// An inline segment already contains its bytes in the forensic
    /// model and therefore does not require an image read.
    fn read_content_segment<R: Readable>(
        &self,
        reader: &mut R,
        entry: &ForensicEntry,
        segment: &ForensicContentSegment,
    ) -> Result<Vec<u8>> {
        match &segment.source {
            ForensicContentSource::Inline(data) => Ok(data.clone()),

            ForensicContentSource::Physical(region) => {
                let bytes_per_cluster = entry.content_layout.bytes_per_cluster;

                if bytes_per_cluster == 0 {
                    return Err(crate::error::ForensisError::InvalidFormat(
                        "Logical content layout has invalid cluster size".to_string(),
                    ));
                }

                let segment_size = segment.byte_count(bytes_per_cluster).ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "Logical content segment size overflow".to_string(),
                    )
                })?;

                let segment_size = usize::try_from(segment_size).map_err(|_| {
                    crate::error::ForensisError::InvalidFormat(
                        "Logical content segment is too large for memory".to_string(),
                    )
                })?;

                self.read_region(reader, region, segment_size)
            }

            ForensicContentSource::Sparse => {
                let bytes_per_cluster = entry.content_layout.bytes_per_cluster;

                if bytes_per_cluster == 0 {
                    return Err(crate::error::ForensisError::InvalidFormat(
                        "Logical content layout has invalid cluster size".to_string(),
                    ));
                }

                let segment_size = segment.byte_count(bytes_per_cluster).ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "Logical content segment size overflow".to_string(),
                    )
                })?;

                let segment_size = usize::try_from(segment_size).map_err(|_| {
                    crate::error::ForensisError::InvalidFormat(
                        "Logical content segment is too large for memory".to_string(),
                    )
                })?;

                /*
                 * A sparse logical segment has no physical
                 * storage. Its logical content is zero-filled.
                 */
                Ok(vec![0u8; segment_size])
            }
        }
    }

    /// Recovers an object according to its logical content layout.
    fn recover_logical_layout<R: Readable>(
        &self,
        reader: &mut R,
        entry: &ForensicEntry,
    ) -> Result<Vec<u8>> {
        let target_size = entry.metadata.real_size.unwrap_or(u64::MAX);

        let mut recovered_data = Vec::new();

        for segment in entry.content_layout.segments() {
            if target_size != u64::MAX && recovered_data.len() as u64 >= target_size {
                break;
            }

            let mut data = self.read_content_segment(reader, entry, segment)?;

            if target_size != u64::MAX {
                let remaining = target_size
                    .checked_sub(recovered_data.len() as u64)
                    .ok_or_else(|| {
                        crate::error::ForensisError::InvalidFormat(
                            "Recovery size calculation overflow".to_string(),
                        )
                    })?;

                if data.len() as u64 > remaining {
                    data.truncate(usize::try_from(remaining).map_err(|_| {
                        crate::error::ForensisError::InvalidFormat(
                            "Recovery size is too large for memory".to_string(),
                        )
                    })?);
                }
            }

            recovered_data.extend_from_slice(&data);
        }

        Ok(recovered_data)
    }
}

impl RecoveryEngine for PhysicalRecoveryEngine {
    /// Recovers one forensic object.
    ///
    /// When a logical content layout is available, it is authoritative.
    ///
    /// The layout preserves the logical order of physical, sparse
    /// and inline segments, allowing fragmented, sparse and resident
    /// content to be reconstructed correctly.
    ///
    /// When no logical layout exists, the engine falls back to the
    /// legacy physical-region recovery path. This preserves compatibility
    /// with forensic entries created by older callers or generic tests.
    fn recover<R: Readable>(
        &self,
        reader: &mut R,
        entry: &ForensicEntry,
    ) -> Result<RecoveryResult> {
        let physical_location = entry.physical_location.clone();

        let target_size = entry.metadata.real_size.unwrap_or(u64::MAX);

        if target_size == 0 {
            return Ok(RecoveryResult::recovered(
                entry.clone(),
                Vec::new(),
                physical_location,
            ));
        }

        /*
         * ---------------------------------------------------------
         * LOGICAL CONTENT RECOVERY
         * ---------------------------------------------------------
         *
         * This is the authoritative path for filesystem parsers
         * that provide a logical content layout.
         */
        if !entry.content_layout.is_empty() {
            let recovered_data = self.recover_logical_layout(reader, entry)?;

            if target_size != u64::MAX && (recovered_data.len() as u64) < target_size {
                return Ok(RecoveryResult::failed(
                    entry.clone(),
                    physical_location,
                    format!(
                        "Logical content contains only {} bytes, \
                             but the object requires {} bytes",
                        recovered_data.len(),
                        target_size
                    ),
                ));
            }

            return Ok(RecoveryResult::recovered(
                entry.clone(),
                recovered_data,
                physical_location,
            ));
        }

        /*
         * ---------------------------------------------------------
         * LEGACY PHYSICAL RECOVERY
         * ---------------------------------------------------------
         *
         * Entries without a logical layout retain the previous
         * physical-region behavior.
         */
        if physical_location.regions.is_empty() {
            return Ok(RecoveryResult::failed(
                entry.clone(),
                physical_location,
                "Forensic object has no physical recovery regions",
            ));
        }

        let mut recovered_data = Vec::new();

        for region in physical_location.regions() {
            if recovered_data.len() as u64 >= target_size {
                break;
            }

            let available_size = self.region_size(region).ok_or_else(|| {
                crate::error::ForensisError::InvalidFormat(
                    "Invalid physical forensic region size".to_string(),
                )
            })?;

            let remaining = target_size
                .checked_sub(recovered_data.len() as u64)
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "Recovery size calculation overflow".to_string(),
                    )
                })?;

            let bytes_to_read = std::cmp::min(available_size, remaining);

            let bytes_to_read = usize::try_from(bytes_to_read).map_err(|_| {
                crate::error::ForensisError::InvalidFormat(
                    "Recovery region is too large for memory".to_string(),
                )
            })?;

            let data = self.read_region(reader, region, bytes_to_read)?;

            recovered_data.extend_from_slice(&data);
        }

        if target_size != u64::MAX && (recovered_data.len() as u64) < target_size {
            return Ok(RecoveryResult::failed(
                entry.clone(),
                physical_location,
                format!(
                    "Physical regions contain only {} bytes, \
                         but the object requires {} bytes",
                    recovered_data.len(),
                    target_size
                ),
            ));
        }

        Ok(RecoveryResult::recovered(
            entry.clone(),
            recovered_data,
            physical_location,
        ))
    }
}

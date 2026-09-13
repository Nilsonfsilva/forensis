use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use forensis_core::{
    disk::ImageReader,
    forensic::ForensicModel,
    progress::{NoProgress, ProgressEvent, ProgressPhase, ProgressReporter, ProgressUnit},
    recovery::{PhysicalRecoveryEngine, RecoveryEngine, RecoveryResult},
    ForensicEntry, ForensicStatus,
};
use sha2::{Digest, Sha256};

use crate::inspect_image;
use crate::InspectionResult;

/// Scope of a recovery operation.
///
/// The recovery API works over forensic objects of the model, not over a
/// filesystem-specific concept of "deleted files". Frontends use this
/// filter to select which objects are candidates for recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFilter {
    /// Objects marked with Deleted status.
    Deleted,
    /// Objects marked with Normal status (live files).
    Normal,
    /// Every recoverable object in the model.
    All,
}

impl RecoveryFilter {
    /// Returns whether an object is a valid candidate for this filter.
    ///
    /// Directories are treated as navigation nodes and are never
    /// recovered as objects.
    pub fn matches(&self, entry: &ForensicEntry) -> bool {
        if entry.is_directory() {
            return false;
        }

        match self {
            RecoveryFilter::Deleted => entry.identity.status == ForensicStatus::Deleted,
            RecoveryFilter::Normal => entry.identity.status == ForensicStatus::Normal,
            RecoveryFilter::All => true,
        }
    }
}

/// Result of comparing the reference content with the recovered content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashComparison {
    /// The reference and recovered SHA-256 digests are identical.
    Identical,

    /// The reference and recovered SHA-256 digests are different.
    Different,

    /// A reference SHA-256 digest was not available.
    ReferenceUnavailable,
}

/// Result of recovering a forensic object.
#[derive(Debug)]
pub struct RecoveredFile {
    /// Original forensic object.
    pub entry: ForensicEntry,

    /// Result produced by the recovery engine.
    pub recovery: RecoveryResult,

    /// Path where the recovered file was written.
    pub output_path: Option<PathBuf>,

    /// SHA-256 digest of the recovered data.
    pub recovered_sha256: Option<String>,

    /// SHA-256 digest of the content reconstructed from the
    /// investigated media.
    pub original_sha256: Option<String>,

    /// Comparison between the reference and recovered SHA-256 digests.
    pub hash_comparison: HashComparison,
}

/// Generates the next shared recovery ticket.
///
/// The ticket counter is shared by every Forensis interface,
/// including the CLI and TUI.
///
/// Tickets are persisted in:
///
/// forensis-recovery/.ticket
///
/// The returned ticket always contains six decimal digits.
pub fn next_recovery_ticket() -> forensis_core::result::Result<String> {
    next_recovery_ticket_in(&PathBuf::from("forensis-recovery"))
}

/// Generates the next recovery ticket inside the specified root directory.
///
/// This helper is separated from `next_recovery_ticket` so tests can
/// use an isolated temporary directory without touching the real
/// recovery ticket counter.
fn next_recovery_ticket_in(root: &Path) -> forensis_core::result::Result<String> {
    fs::create_dir_all(root)?;

    let ticket_path = root.join(".ticket");

    let last = match fs::read_to_string(&ticket_path) {
        Ok(contents) => contents.trim().parse::<u64>().map_err(|_| {
            forensis_core::error::ForensisError::InvalidFormat(format!(
                "Invalid recovery ticket counter in {}",
                ticket_path.display()
            ))
        })?,

        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,

        Err(error) => return Err(error.into()),
    };

    let next = last.checked_add(1).ok_or_else(|| {
        forensis_core::error::ForensisError::InvalidFormat(
            "Recovery ticket counter overflow".to_string(),
        )
    })?;

    fs::write(&ticket_path, next.to_string())?;

    Ok(format!("{:06}", next))
}

/// Recovers all deleted objects from a forensic image.
///
/// This is a convenience that performs the two moments in sequence:
///
/// image
///   -> inspection (builds the ForensicModel)
///   -> Deleted objects of the model
///   -> recovery
pub fn recover_deleted_files(
    image_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let inspection = inspect_image(image_path)?;

    recover_deleted_files_from_result(&inspection, output_dir, &NoProgress)
}

/// Recovers all deleted objects from an already-built inspection result.
///
/// The investigation is performed only once. Recovery then reuses the
/// forensic model without re-reading filesystem metadata.
pub fn recover_deleted_files_from_result(
    inspection: &InspectionResult,
    output_dir: impl AsRef<Path>,
    reporter: &dyn ProgressReporter,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let object_ids = collect_object_ids(inspection, RecoveryFilter::Deleted);

    recover_objects_from_result(inspection, &object_ids, output_dir, reporter)
}

/// Recovers all normal objects from a forensic image.
///
/// This convenience performs the two moments in sequence:
///
/// image
///   -> inspection (builds the ForensicModel)
///   -> Normal objects of the model
///   -> recovery
pub fn recover_normal_files(
    image_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let inspection = inspect_image(image_path)?;

    recover_normal_files_from_result(&inspection, output_dir, &NoProgress)
}

/// Recovers all normal objects from an already-built inspection result.
///
/// The investigation is performed only once. Recovery then reuses the
/// forensic model without re-reading filesystem metadata.
pub fn recover_normal_files_from_result(
    inspection: &InspectionResult,
    output_dir: impl AsRef<Path>,
    reporter: &dyn ProgressReporter,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let object_ids = collect_object_ids(inspection, RecoveryFilter::Normal);

    recover_objects_from_result(inspection, &object_ids, output_dir, reporter)
}

/// Recovers every selectable object from an already-built inspection
/// result.
///
/// This includes objects with Deleted and Normal status. The
/// investigation is performed only once.
pub fn recover_all_from_result(
    inspection: &InspectionResult,
    output_dir: impl AsRef<Path>,
    reporter: &dyn ProgressReporter,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let object_ids = collect_object_ids(inspection, RecoveryFilter::All);

    recover_objects_from_result(inspection, &object_ids, output_dir, reporter)
}

/// Collects the Object IDs of every object matching the filter across
/// all forensic models of the inspection result.
fn collect_object_ids(inspection: &InspectionResult, filter: RecoveryFilter) -> Vec<u64> {
    inspection
        .models
        .iter()
        .filter_map(|model| model.as_ref())
        .flat_map(|model| model.entries())
        .filter(|entry| filter.matches(entry))
        .map(|entry| entry.identity.object_id)
        .collect()
}

/// Recovers a single object by Object ID from an already-built
/// inspection result.
///
/// The Object ID is searched across all forensic models produced by
/// the investigation.
pub fn recover_object_from_result(
    inspection: &InspectionResult,
    object_id: u64,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<RecoveredFile> {
    let output_dir = output_dir.as_ref();

    fs::create_dir_all(output_dir)?;

    let (model_index, entry) = find_object(inspection, object_id).ok_or_else(|| {
        forensis_core::error::ForensisError::InvalidFormat(format!(
            "Forensic object with Object ID {} was not found",
            object_id
        ))
    })?;

    let mut reader = open_reader(inspection)?;

    let engine = create_engine(inspection, model_index);

    let recovery = engine.recover(&mut reader, entry)?;

    finalize_recovery(output_dir, entry, recovery)
}

/// Recovers several objects by Object ID from an already-built
/// inspection result.
///
/// The investigation is performed only once. Every selected object is
/// then recovered from the same forensic model. Progress is reported
/// per object so frontends can display "recuperando objeto i de N".
pub fn recover_objects_from_result(
    inspection: &InspectionResult,
    object_ids: &[u64],
    output_dir: impl AsRef<Path>,
    reporter: &dyn ProgressReporter,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let output_dir = output_dir.as_ref();

    fs::create_dir_all(output_dir)?;

    if object_ids.is_empty() {
        reporter.report(ProgressEvent::completed());

        return Ok(Vec::new());
    }

    let mut reader = open_reader(inspection)?;

    let total = object_ids.len() as u64;

    let mut recovered_files = Vec::new();

    for (index, object_id) in object_ids.iter().enumerate() {
        reporter.report(ProgressEvent::new(
            ProgressPhase::Recovering,
            index as u64 + 1,
            total,
            ProgressUnit::Objects,
        ));

        let Some((model_index, entry)) = find_object(inspection, *object_id) else {
            continue;
        };

        let engine = create_engine(inspection, model_index);

        let recovery = engine.recover(&mut reader, entry)?;

        recovered_files.push(finalize_recovery(output_dir, entry, recovery)?);
    }

    reporter.report(ProgressEvent::completed());

    Ok(recovered_files)
}

/// Recovers a single object by Object ID from a forensic image.
///
/// This convenience performs the investigation and then recovers the
/// selected object without re-reading filesystem metadata.
pub fn recover_object(
    image_path: impl AsRef<Path>,
    object_id: u64,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<RecoveredFile> {
    let inspection = inspect_image(image_path)?;

    recover_object_from_result(&inspection, object_id, output_dir)
}

/// Recovers all selectable objects from a forensic image.
///
/// This is the general recovery operation: every recoverable object
/// (Deleted and Normal) is recovered without re-reading filesystem
/// metadata.
///
/// Future versions may coordinate additional methods,
/// such as file carving.
pub fn recover_all(
    image_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let inspection = inspect_image(image_path)?;

    recover_all_from_result(&inspection, output_dir, &NoProgress)
}

/// Recovers several objects by Object ID from a forensic image.
///
/// This convenience performs the investigation and then recovers every
/// selected object without re-reading filesystem metadata.
pub fn recover_objects(
    image_path: impl AsRef<Path>,
    object_ids: &[u64],
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    let inspection = inspect_image(image_path)?;

    recover_objects_from_result(&inspection, object_ids, output_dir, &NoProgress)
}

/// Collects the recoverable candidate objects of a forensic model.
///
/// The tree is traversed from `root_id` down, defensively, skipping
/// directories (navigation nodes) and keeping only objects that match
/// the filter. Frontends (CLI and TUI) use this to build their recovery
/// selection list from the same filesystem-independent contract.
pub fn collect_recoverable_entries(
    model: &ForensicModel,
    root_id: u64,
    filter: RecoveryFilter,
) -> Vec<ForensicEntry> {
    let entries = model.entries();

    let mut children = HashMap::<u64, Vec<&ForensicEntry>>::new();

    for entry in entries {
        if let Some(parent_id) = entry.hierarchy.parent_id {
            children.entry(parent_id).or_default().push(entry);
        }
    }

    let mut result = Vec::new();

    let mut stack = vec![root_id];

    /*
     * A forensic hierarchy must be traversed defensively.
     *
     * Filesystem metadata can be inconsistent or corrupted.
     * Without a visited set, a directory cycle such as
     * A -> B -> C -> A would cause an infinite traversal.
     */
    let mut visited = HashSet::new();

    while let Some(parent_id) = stack.pop() {
        if !visited.insert(parent_id) {
            continue;
        }

        let children_of_parent = match children.get(&parent_id) {
            Some(children) => children,
            None => continue,
        };

        for entry in children_of_parent {
            if entry.is_directory() {
                stack.push(entry.identity.object_id);
                continue;
            }

            if filter.matches(entry) {
                result.push((*entry).clone());
            }
        }
    }

    result.sort_by(|a, b| {
        a.identity
            .path
            .to_lowercase()
            .cmp(&b.identity.path.to_lowercase())
    });

    result
}

/// Finds an object across all models of the inspection result.
///
/// Returns the model index and the forensic entry. The model index is
/// required later to build the recovery engine with the correct
/// partition offset.
fn find_object(inspection: &InspectionResult, object_id: u64) -> Option<(usize, &ForensicEntry)> {
    for (model_index, model) in inspection.models.iter().enumerate() {
        if let Some(entry) = model.as_ref().and_then(|model| model.entry(object_id)) {
            return Some((model_index, entry));
        }
    }

    None
}

/// Opens an image reader from the inspection result.
fn open_reader(inspection: &InspectionResult) -> forensis_core::result::Result<ImageReader> {
    let image_path = inspection.image.to_string_lossy().to_string();

    ImageReader::open(&image_path)
}

/// Builds the final `RecoveredFile` from a recovery result.
///
/// A recovered object is written to the output directory and its
/// SHA-256 digest is calculated. An object that the engine could not
/// recover is returned without an output path.
fn finalize_recovery(
    output_dir: &Path,
    entry: &ForensicEntry,
    recovery: RecoveryResult,
) -> forensis_core::result::Result<RecoveredFile> {
    if !recovery.is_recovered() {
        return Ok(RecoveredFile {
            entry: entry.clone(),
            original_sha256: recovery.original_sha256.clone(),
            recovery,
            output_path: None,
            recovered_sha256: None,
            hash_comparison: HashComparison::ReferenceUnavailable,
        });
    }

    let original_sha256 = recovery.original_sha256.clone();

    let data = recovery.data().unwrap_or(&[]);

    let recovered_sha256 = calculate_sha256(data);

    let hash_comparison = compare_hashes(original_sha256.as_deref(), Some(&recovered_sha256));

    let output_path = write_recovered_file(output_dir, entry, data)?;

    Ok(RecoveredFile {
        entry: entry.clone(),
        recovery,
        output_path: Some(output_path),
        recovered_sha256: Some(recovered_sha256),
        original_sha256,
        hash_comparison,
    })
}

/// Creates the physical recovery engine for a partition/model.
///
/// Filesystem-produced regions are relative to the beginning
/// of the partition.
fn create_engine(
    inspection: &crate::InspectionResult,
    model_index: usize,
) -> PhysicalRecoveryEngine {
    let partition_offset = inspection
        .partitions
        .get(model_index)
        .and_then(|partition| partition.start_sector.checked_mul(512))
        .unwrap_or(0);

    PhysicalRecoveryEngine::new(partition_offset, 512)
}

/// Calculates the SHA-256 digest of recovered data.
///
/// The digest is returned as a lowercase hexadecimal string.
fn calculate_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("{:x}", digest)
}

/// Compares a reference SHA-256 digest with a recovered SHA-256 digest.
fn compare_hashes(original_sha256: Option<&str>, recovered_sha256: Option<&str>) -> HashComparison {
    match (original_sha256, recovered_sha256) {
        (Some(original), Some(recovered)) if original == recovered => HashComparison::Identical,

        (Some(_), Some(_)) => HashComparison::Different,

        _ => HashComparison::ReferenceUnavailable,
    }
}

/// Writes a recovered object to the output directory.
///
/// This first implementation uses only the object name.
/// If a file with the same name already exists, a suffix
/// based on the Object ID is used to prevent overwriting.
fn write_recovered_file(
    output_dir: &Path,
    entry: &ForensicEntry,
    data: &[u8],
) -> forensis_core::result::Result<PathBuf> {
    let file_name = Path::new(&entry.identity.name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("recovered_file");

    let mut output_path = output_dir.join(file_name);

    if output_path.exists() {
        let original = Path::new(file_name);

        let stem = original
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("recovered_file");

        let extension = original.extension().and_then(|value| value.to_str());

        let unique_name = match extension {
            Some(extension) => {
                format!("{}_{}.{}", stem, entry.identity.object_id, extension)
            }

            None => {
                format!("{}_{}", stem, entry.identity.object_id)
            }
        };

        output_path = output_dir.join(unique_name);
    }

    fs::write(&output_path, data)?;

    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{calculate_sha256, compare_hashes, next_recovery_ticket_in, HashComparison};

    use forensis_core::forensic::{
        ForensicAllocation, ForensicEntry, ForensicEntryKind, ForensicFilesystem,
        ForensicHierarchy, ForensicIdentity, ForensicMetadata, ForensicModel, ForensicObject,
        ForensicPhysicalLocation, ForensicSource, ForensicStatus,
    };

    #[test]
    fn collect_recoverable_entries_handles_cycles_and_filters() {
        use crate::recovery::{collect_recoverable_entries, RecoveryFilter};

        let entries = vec![
            ForensicEntry::new(
                ForensicIdentity::new(
                    "A",
                    "/A",
                    ForensicEntryKind::Directory,
                    ForensicStatus::Normal,
                    10,
                ),
                ForensicHierarchy::new(Some(30)),
                ForensicMetadata::new(Some(0), Some(0)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 10),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "B",
                    "/A/B",
                    ForensicEntryKind::Directory,
                    ForensicStatus::Normal,
                    20,
                ),
                ForensicHierarchy::new(Some(10)),
                ForensicMetadata::new(Some(0), Some(0)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 20),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "C",
                    "/A/B/C",
                    ForensicEntryKind::Directory,
                    ForensicStatus::Normal,
                    30,
                ),
                ForensicHierarchy::new(Some(20)),
                ForensicMetadata::new(Some(0), Some(0)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 30),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "deleted.txt",
                    "/A/deleted.txt",
                    ForensicEntryKind::File,
                    ForensicStatus::Deleted,
                    40,
                ),
                ForensicHierarchy::new(Some(10)),
                ForensicMetadata::new(Some(10), Some(10)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 40),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "live.txt",
                    "/A/live.txt",
                    ForensicEntryKind::File,
                    ForensicStatus::Normal,
                    50,
                ),
                ForensicHierarchy::new(Some(10)),
                ForensicMetadata::new(Some(10), Some(10)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 50),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
        ];

        let model = ForensicModel::new(
            ForensicSource::new(None, ForensicFilesystem::Ntfs),
            4,
            entries,
        );

        let deleted = collect_recoverable_entries(&model, 10, RecoveryFilter::Deleted);
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].identity.object_id, 40);

        let normal = collect_recoverable_entries(&model, 10, RecoveryFilter::Normal);
        assert_eq!(normal.len(), 1);
        assert_eq!(normal[0].identity.object_id, 50);

        let all = collect_recoverable_entries(&model, 10, RecoveryFilter::All);
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|entry| !entry.is_directory()));
    }

    #[test]
    fn calculate_sha256_returns_expected_digest() {
        let data = b"1234567890";

        let digest = calculate_sha256(data);

        assert_eq!(
            digest,
            "c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646"
        );
    }

    #[test]
    fn identical_hashes_are_detected() {
        let hash = "abc123";

        assert_eq!(
            compare_hashes(Some(hash), Some(hash)),
            HashComparison::Identical
        );
    }

    #[test]
    fn different_hashes_are_detected() {
        assert_eq!(
            compare_hashes(Some("abc123"), Some("def456")),
            HashComparison::Different
        );
    }

    #[test]
    fn missing_reference_is_detected() {
        assert_eq!(
            compare_hashes(None, Some("abc123")),
            HashComparison::ReferenceUnavailable
        );
    }

    #[test]
    fn recovery_ticket_has_six_digits_and_increments() {
        let temp = tempfile::tempdir().unwrap();

        fs::write(temp.path().join(".ticket"), "41").unwrap();

        let ticket = next_recovery_ticket_in(temp.path()).unwrap();

        assert_eq!(ticket, "000042");

        let next_ticket = next_recovery_ticket_in(temp.path()).unwrap();

        assert_eq!(next_ticket, "000043");
    }
}

use std::fs;
use std::path::{Path, PathBuf};

use forensis_core::{
    disk::ImageReader,
    recovery::{PhysicalRecoveryEngine, RecoveryEngine, RecoveryResult},
    ForensicEntry, ForensicStatus,
};
use sha2::{Digest, Sha256};

use crate::inspect_image;

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
fn next_recovery_ticket_in(
    root: &Path,
) -> forensis_core::result::Result<String> {
    fs::create_dir_all(root)?;

    let ticket_path = root.join(".ticket");

    let last = match fs::read_to_string(&ticket_path) {
        Ok(contents) => contents
            .trim()
            .parse::<u64>()
            .map_err(|_| {
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
/// The flow is:
///
/// image
///   -> inspection
///   -> ForensicModel
///   -> Deleted objects
///   -> PhysicalRecoveryEngine
///   -> reference content
///   -> original SHA-256
///   -> recovery result
///   -> recovered SHA-256
///   -> hash comparison
pub fn recover_deleted_files(
    image_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    recover_matching_entries(image_path, output_dir, |entry| {
        entry.identity.status == ForensicStatus::Deleted
    })
}

/// Recovers a single object by Object ID.
///
/// The Object ID is searched across all forensic models
/// produced by the investigation.
pub fn recover_object(
    image_path: impl AsRef<Path>,
    object_id: u64,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<RecoveredFile> {
    let image_path = image_path.as_ref();
    let output_dir = output_dir.as_ref();

    let inspection = inspect_image(image_path)?;

    fs::create_dir_all(output_dir)?;

    let image_path_string = image_path.to_string_lossy().to_string();

    let mut reader = ImageReader::open(&image_path_string)?;

    for (model_index, model) in inspection.models.iter().enumerate() {
        let Some(model) = model else {
            continue;
        };

        let Some(entry) = model
            .entries()
            .iter()
            .find(|entry| entry.identity.object_id == object_id)
        else {
            continue;
        };

        let engine = create_engine(&inspection, model_index);

        let recovery = engine.recover(&mut reader, entry)?;

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

        let hash_comparison =
            compare_hashes(original_sha256.as_deref(), Some(&recovered_sha256));

        let output_path = write_recovered_file(output_dir, entry, data)?;

        return Ok(RecoveredFile {
            entry: entry.clone(),
            recovery,
            output_path: Some(output_path),
            recovered_sha256: Some(recovered_sha256),
            original_sha256,
            hash_comparison,
        });
    }

    Err(forensis_core::error::ForensisError::InvalidFormat(format!(
        "Forensic object with Object ID {} was not found",
        object_id
    )))
}

/// Recovers all objects with Deleted status.
///
/// This is the general recovery operation in the first
/// implementation stage.
///
/// Future versions may coordinate additional methods,
/// such as file carving.
pub fn recover_all(
    image_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> forensis_core::result::Result<Vec<RecoveredFile>> {
    recover_deleted_files(image_path, output_dir)
}

/// Implements the generic search for forensic objects.
///
/// The recovery layer remains independent of NTFS, EXT4,
/// or any filesystem-specific structure.
fn recover_matching_entries<F>(
    image_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    predicate: F,
) -> forensis_core::result::Result<Vec<RecoveredFile>>
where
    F: Fn(&ForensicEntry) -> bool,
{
    let image_path = image_path.as_ref();
    let output_dir = output_dir.as_ref();

    let inspection = inspect_image(image_path)?;

    fs::create_dir_all(output_dir)?;

    let image_path_string = image_path.to_string_lossy().to_string();

    let mut reader = ImageReader::open(&image_path_string)?;

    let mut recovered_files = Vec::new();

    for (model_index, model) in inspection.models.iter().enumerate() {
        let Some(model) = model else {
            continue;
        };

        let engine = create_engine(&inspection, model_index);

        for entry in model.entries() {
            if !predicate(entry) {
                continue;
            }

            let recovery = engine.recover(&mut reader, entry)?;

            if !recovery.is_recovered() {
                recovered_files.push(RecoveredFile {
                    entry: entry.clone(),
                    original_sha256: recovery.original_sha256.clone(),
                    recovery,
                    output_path: None,
                    recovered_sha256: None,
                    hash_comparison: HashComparison::ReferenceUnavailable,
                });

                continue;
            }

            let original_sha256 = recovery.original_sha256.clone();

            let data = recovery.data().unwrap_or(&[]);
            let recovered_sha256 = calculate_sha256(data);

            let hash_comparison =
                compare_hashes(original_sha256.as_deref(), Some(&recovered_sha256));

            let output_path = write_recovered_file(output_dir, entry, data)?;

            recovered_files.push(RecoveredFile {
                entry: entry.clone(),
                recovery,
                output_path: Some(output_path),
                recovered_sha256: Some(recovered_sha256),
                original_sha256,
                hash_comparison,
            });
        }
    }

    Ok(recovered_files)
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
fn compare_hashes(
    original_sha256: Option<&str>,
    recovered_sha256: Option<&str>,
) -> HashComparison {
    match (original_sha256, recovered_sha256) {
        (Some(original), Some(recovered)) if original == recovered => {
            HashComparison::Identical
        }

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

        let extension = original
            .extension()
            .and_then(|value| value.to_str());

        let unique_name = match extension {
            Some(extension) => {
                format!(
                    "{}_{}.{}",
                    stem,
                    entry.identity.object_id,
                    extension
                )
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

    use super::{
        calculate_sha256,
        compare_hashes,
        next_recovery_ticket_in,
        HashComparison,
    };

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

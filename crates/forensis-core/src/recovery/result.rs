use crate::forensic::{ForensicEntry, ForensicPhysicalLocation};

/// Represents the result of a forensic recovery operation.
///
/// The recovery layer is filesystem-independent.
///
/// Filesystem-specific parsers are responsible for producing
/// `ForensicEntry` and physical-location information.
/// Recovery consumes that common representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResult {
    /// Original forensic entry associated with the recovery.
    pub entry: ForensicEntry,

    /// Indicates whether the object was successfully recovered.
    pub recovered: bool,

    /// Recovered file content when available.
    ///
    /// `None` means that the object could not provide recoverable
    /// content, or that the recovery operation did not read data.
    pub data: Option<Vec<u8>>,

    /// SHA-256 digest of the content reconstructed from the
    /// investigated media.
    ///
    /// This represents the reference content available on the
    /// forensic image before the recovered result is written.
    pub original_sha256: Option<String>,

    /// Physical regions used during recovery.
    pub physical_location: ForensicPhysicalLocation,

    /// Human-readable explanation when recovery is incomplete
    /// or unsuccessful.
    pub reason: Option<String>,
}

impl RecoveryResult {
    /// Creates a successful recovery result.
    pub fn recovered(
        entry: ForensicEntry,
        data: Vec<u8>,
        physical_location: ForensicPhysicalLocation,
    ) -> Self {
        let original_sha256 = Some(calculate_sha256(&data));

        Self {
            entry,
            recovered: true,
            data: Some(data),
            original_sha256,
            physical_location,
            reason: None,
        }
    }

    /// Creates a recovery result for an object that could not
    /// be completely recovered.
    pub fn failed(
        entry: ForensicEntry,
        physical_location: ForensicPhysicalLocation,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            entry,
            recovered: false,
            data: None,
            original_sha256: None,
            physical_location,
            reason: Some(reason.into()),
        }
    }

    /// Returns true when the object was recovered successfully.
    pub fn is_recovered(&self) -> bool {
        self.recovered
    }

    /// Returns the recovered data when available.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Returns the SHA-256 digest calculated from the
    /// content reconstructed from the forensic image.
    pub fn original_sha256(&self) -> Option<&str> {
        self.original_sha256.as_deref()
    }

    /// Returns the forensic entry associated with this result.
    pub fn entry(&self) -> &ForensicEntry {
        &self.entry
    }

    /// Returns the physical location used by the recovery.
    pub fn physical_location(&self) -> &ForensicPhysicalLocation {
        &self.physical_location
    }

    /// Returns the recovery failure reason, when present.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// Calculates the SHA-256 digest of the supplied data.
///
/// The digest is returned as a lowercase hexadecimal string.
fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(data);

    format!("{:x}", digest)
}

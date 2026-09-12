use crate::error::ForensisError;
use crate::result::Result;

use super::file_name::FileNameAttribute;
use super::index_entry::IndexEntry;

/// Represents a logical entry inside an NTFS directory.
///
/// This structure sits above the raw NTFS INDEX_ENTRY
/// and FILE_NAME structures and provides a cleaner
/// representation for the forensic layer.
#[derive(Debug, Clone)]
pub struct NtfsDirectoryEntry {
    /// MFT record number of the referenced file.
    ///
    /// This is the lower 48-bit MFT record number extracted
    /// from the raw NTFS file reference.
    pub file_reference: u64,

    /// Parsed FILE_NAME attribute.
    pub file_name: FileNameAttribute,
}

impl NtfsDirectoryEntry {
    /// Builds a directory entry from an NTFS INDEX_ENTRY.
    ///
    /// The raw INDEX_ENTRY file reference contains both:
    ///
    /// - the MFT record number in the lower 48 bits;
    /// - the sequence number in the upper 16 bits.
    ///
    /// The forensic directory layer only stores the actual
    /// MFT record number in `file_reference`.
    pub fn from_index_entry(entry: &IndexEntry) -> Result<Self> {
        /*
         * An INDEX_ENTRY without a key can be structurally
         * valid, for example the terminating INDEX_ENTRY.
         *
         * Such an entry cannot be interpreted as FILE_NAME.
         */

        if entry.key().is_empty() {
            return Err(ForensisError::InvalidFormat(
                "INDEX_ENTRY contains no FILE_NAME key".to_string(),
            ));
        }

        /*
         * Parse the raw key as an NTFS FILE_NAME attribute.
         */

        let file_name = entry.file_name()?;

        /*
         * IMPORTANT:
         *
         * `entry.file_reference` is the complete NTFS
         * 64-bit file reference.
         *
         * It contains:
         *
         *   lower 48 bits -> MFT record number
         *   upper 16 bits -> sequence number
         *
         * The directory abstraction must expose only
         * the MFT record number.
         *
         * Therefore we use `mft_record()` instead of
         * copying the raw `file_reference`.
         */

        Ok(Self {
            file_reference: entry.mft_record(),

            file_name,
        })
    }

    /// Returns true if this entry represents a directory.
    pub fn is_directory(&self) -> bool {
        self.file_name.is_directory()
    }

    /// Returns true if this entry represents a regular file.
    pub fn is_file(&self) -> bool {
        self.file_name.is_file()
    }

    /// Returns the file name.
    pub fn name(&self) -> &str {
        &self.file_name.name
    }

    /// Returns the parent directory MFT record.
    ///
    /// The FILE_NAME parser has already separated the
    /// complete NTFS file reference into:
    ///
    ///   parent_record
    ///   parent_sequence
    ///
    /// Therefore this method returns the already-decoded
    /// MFT record number directly.
    pub fn parent_reference(&self) -> u64 {
        self.file_name.parent_record
    }
}

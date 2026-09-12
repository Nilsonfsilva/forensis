use crate::result::Result;

use super::file_name::FileNameAttribute;
use super::index_allocation::IndexAllocation;
use super::index_entry::IndexEntry;
use super::index_root::IndexRoot;

/// Represents an NTFS directory.
#[derive(Debug, Clone)]
pub struct NtfsDirectory {
    /// MFT record number of the directory.
    pub mft_record: u64,

    /// Directory index entries.
    ///
    /// These are kept in their structural form.
    /// Not every INDEX_ENTRY necessarily contains a
    /// FILE_NAME key that can be interpreted.
    pub entries: Vec<IndexEntry>,
}

impl NtfsDirectory {
    /// Builds a directory from its INDEX_ROOT attribute.
    ///
    /// An INDEX_ROOT is allowed to contain no normal
    /// entries. In that case, the directory may have
    /// its entries stored in INDEX_ALLOCATION.
    pub fn from_index_root(mft_record: u64, root: &IndexRoot) -> Result<Self> {
        Ok(Self {
            mft_record,
            entries: root.entries.clone(),
        })
    }

    /// Adds entries from INDEX_ALLOCATION.
    pub fn add_index_allocation(&mut self, allocation: &IndexAllocation) -> Result<()> {
        self.entries.extend(allocation.entries().iter().cloned());

        Ok(())
    }

    /// Returns the number of structural directory entries.
    ///
    /// This count refers to INDEX_ENTRY structures and therefore
    /// may include entries that do not contain a valid FILE_NAME
    /// key.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the FILE_NAME attribute of a specific entry.
    ///
    /// Unlike `file_names()`, this method is strict: if the
    /// requested INDEX_ENTRY does not contain a valid FILE_NAME,
    /// the parsing error is returned to the caller.
    pub fn file_name(&self, index: usize) -> Result<FileNameAttribute> {
        let entry = self.entries.get(index).ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat(
                "Directory entry index out of range".to_string(),
            )
        })?;

        entry.file_name()
    }

    /// Returns all valid FILE_NAME attributes contained in
    /// the directory.
    ///
    /// NTFS directory indexes can contain structural entries
    /// that do not provide a FILE_NAME value that can be
    /// interpreted by the forensic layer.
    ///
    /// Such entries must not abort the complete directory
    /// investigation. They are therefore skipped here.
    pub fn file_names(&self) -> Result<Vec<FileNameAttribute>> {
        let mut names = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            match entry.file_name() {
                Ok(file_name) => {
                    names.push(file_name);
                }

                Err(_) => {
                    /*
                     * The INDEX_ENTRY itself is structurally
                     * valid, but its key cannot be interpreted
                     * as a FILE_NAME attribute.
                     *
                     * Keep investigating the remaining entries
                     * instead of aborting the entire directory.
                     */
                    continue;
                }
            }
        }

        Ok(names)
    }
}

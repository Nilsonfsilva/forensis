//! Parsed representation of an NTFS MFT record.
//!
//! This module contains the high-level representation
//! produced after interpreting raw MFT attributes.

use crate::filesystem::ntfs::{DataAttribute, FileNameAttribute, IndexRoot, StandardInformation};

/// Represents an interpreted NTFS MFT record.
///
/// Unlike `MftRecord`, which contains raw bytes,
/// this structure contains forensic information
/// extracted from NTFS attributes.
#[derive(Debug, Clone)]
pub struct ParsedMftRecord {
    /// MFT record number.
    pub index: u64,

    /// Flags from the NTFS MFT record header.
    ///
    /// These flags describe the state of the MFT record itself.
    /// They are different from the FILE_ATTRIBUTE_* flags
    /// contained in the `$FILE_NAME` attribute.
    pub mft_flags: u16,

    /// Standard information metadata.
    ///
    /// Contains timestamps, permissions,
    /// and file flags.
    pub standard_information: Option<StandardInformation>,

    /// File name information.
    ///
    /// NTFS may contain more than one FILE_NAME
    /// attribute, therefore this is a vector.
    pub file_names: Vec<FileNameAttribute>,

    /// NTFS $DATA attribute.
    ///
    /// Contains file size information and,
    /// for non-resident data, the data runs
    /// describing where the file data is stored.
    pub data: Option<DataAttribute>,

    /// NTFS directory index stored in INDEX_ROOT.
    ///
    /// This is present when the MFT record contains
    /// a resident INDEX_ROOT attribute.
    pub index_root: Option<IndexRoot>,
}

impl ParsedMftRecord {
    /// Creates an empty parsed MFT record.
    pub fn new(index: u64) -> Self {
        Self {
            index,

            mft_flags: 0,

            standard_information: None,

            file_names: Vec::new(),

            data: None,

            index_root: None,
        }
    }
}

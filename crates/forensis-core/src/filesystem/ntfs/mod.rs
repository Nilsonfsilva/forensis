//! NTFS filesystem implementation.
//!
//! This module provides the public interface for NTFS analysis.
//!
//! Internal components handle:
//!
//! - NTFS boot sector parsing
//! - Master File Table (MFT) reading
//! - MFT record interpretation
//! - NTFS attribute parsing
//! - File metadata extraction

pub mod boot_sector;

pub mod mft_reader;

pub mod mft_record;

pub mod mft_parser;

pub mod mft_attribute;

pub mod standard_information;

pub mod file_name;

pub mod parsed_record;

pub mod data_attribute;

pub mod data_run;

pub mod data_run_reader;

pub mod file_content;

pub mod index_root;

pub mod index_allocation;

pub mod index_entry;

pub mod volume;

pub mod volume_information;

pub mod attr_def;

pub mod log_file;

pub mod upcase;

pub mod bitmap;

pub mod secure;

pub mod badclus;

pub mod directory;

pub mod directory_entry;

pub mod investigation_entry;

pub mod investigation;

//
// Public NTFS API.
//
// These re-exports intentionally hide the internal
// module organization from the rest of the crate.
//

pub use boot_sector::{NtfsBootSector, NtfsFileSystem};

pub use mft_reader::NtfsMftReader;

pub use mft_record::MftRecord;

pub use mft_parser::MftParser;

pub use mft_attribute::{AttributeType, MftAttribute};

pub use standard_information::StandardInformation;

pub use file_name::FileNameAttribute;

pub use attr_def::{AttrDef, AttributeDefinition};

pub use log_file::{LogFile, LogRecord, RestartArea};

pub use index_root::IndexRoot;

pub use parsed_record::ParsedMftRecord;

pub use data_attribute::DataAttribute;

pub use data_run::DataRun;

pub use data_run_reader::DataRunReader;

pub use file_content::FileContentReader;

pub use bitmap::Bitmap;

pub use index_allocation::IndexAllocation;

pub use index_entry::IndexEntry;

pub use volume::NtfsVolume;

pub use volume_information::VolumeInformation;

pub use upcase::UpCase;

pub use secure::Secure;

pub use badclus::BadClusters;

pub use directory::NtfsDirectory;

pub use directory_entry::NtfsDirectoryEntry;

pub use investigation_entry::InvestigationEntry;

pub use investigation::Investigation;

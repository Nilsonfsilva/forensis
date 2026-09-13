//! exFAT filesystem support.
//!
//! exFAT uses a classic FAT chain of cluster pointers similar to FAT32,
//! but with a larger on-disk layout, native UTF-16 long file names and
//! structured 32-byte directory entries. Deleted files are recoverable
//! while the FAT chain and the directory name have not been overwritten.
//!
//! The modules implement the boot sector, the data reader, the directory
//! walk and the forensic model mapping needed to investigate allocated
//! and deleted entries.

pub mod boot;
pub mod directory;
pub mod filesystem;
pub mod investigation;
pub mod investigation_entry;
pub mod reader;

pub use boot::ExFatBootSector;
pub use directory::{parse_directory_entries, ExFatDirectoryEntry};
pub use filesystem::ExFatFilesystem;
pub use investigation::{investigate_filesystem, ExFatInvestigation};
pub use investigation_entry::ExFatInvestigationEntry;
pub use reader::ExFatReader;

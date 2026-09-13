//! FAT32 filesystem support.
//!
//! FAT32 keeps the classic FAT chain of cluster pointers, which makes
//! deleted files recoverable while the FAT chain and the directory
//! name have not been overwritten yet. The modules implement the
//! boot sector, the data reader, the directory walk and the forensic
//! model mapping needed to investigate allocated and deleted entries.

pub mod boot;
pub mod directory;
pub mod filesystem;
pub mod investigation;
pub mod investigation_entry;
pub mod reader;

pub use boot::Fat32BootSector;
pub use directory::{lfn_checksum, parse_directory_entries, Fat32DirectoryEntry};
pub use filesystem::Fat32Filesystem;
pub use investigation::{investigate_filesystem, Fat32Investigation};
pub use investigation_entry::Fat32InvestigationEntry;
pub use reader::Fat32Reader;

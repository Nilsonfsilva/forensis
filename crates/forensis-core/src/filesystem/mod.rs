//! Filesystem abstraction layer.

pub mod detector;
pub mod traits;

pub mod exfat;
pub mod ext4;
pub mod fat32;
pub mod ntfs;

pub use detector::{FileSystemDetector, FileSystemType};

pub use traits::FileSystem;

pub use ntfs::*;

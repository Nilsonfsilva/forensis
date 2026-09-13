//! Main library entry point for Forensis Core.

pub mod error;
pub mod platform;
pub mod progress;
pub mod result;
pub mod traits;
pub mod types;

pub mod disk;
pub mod filesystem;
pub mod partition;

pub mod forensic;
pub mod recovery;
pub mod source;

// Core types
pub use error::ForensisError;
pub use platform::{Architecture, Platform};
pub use result::Result;

pub use progress::{NoProgress, ProgressEvent, ProgressPhase, ProgressReporter, ProgressUnit};

pub use traits::{PartitionTableReader, Readable};

pub use types::{ByteOffset, ByteSize, Cluster, Sector};

// Storage layer
pub use disk::*;

// Partition layer
pub use partition::*;

pub use filesystem::{FileSystemDetector, FileSystemType};

pub use filesystem::ntfs::{AttributeType, MftAttribute};

pub use forensic::{ForensicEntry, ForensicEntryKind, ForensicFilesystem, ForensicStatus};

pub use recovery::{RecoveryEngine, RecoveryResult};

// Evidence source layer
pub use source::{EvidenceSource, EvidenceSourceKind};

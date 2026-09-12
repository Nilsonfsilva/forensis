//! Application layer for Forensis.
//!
//! This crate contains application use cases shared by
//! different user interfaces such as the CLI and TUI.

pub mod inspection;
pub mod recovery;
pub mod source;

pub use inspection::{inspect_image, InspectionResult};

pub use recovery::{
    next_recovery_ticket, recover_all, recover_deleted_files, recover_object, RecoveredFile,
};

pub use source::{discover_sources, resolve_source};

pub use forensis_core::{
    filesystem::FileSystemType,
    forensic::{
        ForensicAllocation, ForensicEntry, ForensicEntryKind, ForensicFilesystem,
        ForensicHierarchy, ForensicIdentity, ForensicMetadata, ForensicModel, ForensicObject,
        ForensicPhysicalLocation, ForensicSource, ForensicStatus, ForensicTree, ForensicTreeNode,
    },
    EvidenceSource, EvidenceSourceKind, Partition, PartitionTableType, PartitionType,
};

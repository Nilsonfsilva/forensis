//! Application layer for Forensis.
//!
//! This crate contains application use cases shared by
//! different user interfaces such as the CLI and TUI.

pub mod inspection;
pub mod recovery;
pub mod source;

pub use inspection::{inspect_image, inspect_image_with_progress, InspectionResult};

pub use recovery::{
    collect_recoverable_entries, next_recovery_ticket, recover_all, recover_all_from_result,
    recover_deleted_files, recover_deleted_files_from_result, recover_normal_files,
    recover_normal_files_from_result, recover_object, recover_object_from_result, recover_objects,
    recover_objects_from_result, RecoveredFile, RecoveryFilter,
};

pub use source::{discover_sources, resolve_source};

pub use forensis_core::{
    filesystem::FileSystemType,
    forensic::{
        ForensicAllocation, ForensicEntry, ForensicEntryKind, ForensicFilesystem,
        ForensicHierarchy, ForensicIdentity, ForensicMetadata, ForensicModel, ForensicObject,
        ForensicPhysicalLocation, ForensicSource, ForensicStatus, ForensicTree, ForensicTreeNode,
    },
    progress::{ProgressEvent, ProgressPhase, ProgressReporter, ProgressUnit},
    EvidenceSource, EvidenceSourceKind, Partition, PartitionTableType, PartitionType,
};

//! Progress reporting primitives for long-running forensic operations.
//!
//! This module defines a filesystem-independent progress contract.
//! Concrete frontends such as the CLI and TUI decide how progress is displayed.

/// Describes the current phase of a forensic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressPhase {
    /// Detecting the filesystem under investigation.
    DetectingFilesystem,

    /// Reading filesystem metadata required for the investigation.
    ReadingMetadata,

    /// Reading filesystem data required for the investigation.
    ReadingData,

    /// Processing filesystem records, inodes, directory clusters, or similar units.
    ProcessingRecords,

    /// Building the common forensic representation.
    BuildingEntries,

    /// Recovering forensic objects from an already-built model.
    Recovering,

    /// The operation has completed.
    Completed,
}

/// Describes the unit represented by the progress counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressUnit {
    /// Generic filesystem records.
    Records,

    /// NTFS MFT records.
    MftRecords,

    /// EXT4 inodes.
    Inodes,

    /// Directory clusters used by FAT32/exFAT directory traversal.
    DirectoryClusters,

    /// Bytes being processed.
    Bytes,

    /// Forensic objects selected for recovery.
    Objects,

    /// No specific unit applies.
    None,
}

/// A progress event emitted by a long-running forensic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressEvent {
    /// Current phase of the operation.
    pub phase: ProgressPhase,

    /// Current amount of work completed.
    pub current: u64,

    /// Total amount of work, when a reliable denominator is available.
    pub total: Option<u64>,

    /// Unit represented by `current` and `total`.
    pub unit: ProgressUnit,
}

impl ProgressEvent {
    /// Creates a progress event with a known total.
    pub fn new(phase: ProgressPhase, current: u64, total: u64, unit: ProgressUnit) -> Self {
        Self {
            phase,
            current,
            total: Some(total),
            unit,
        }
    }

    /// Creates a progress event when no reliable total is available.
    pub fn indeterminate(phase: ProgressPhase, current: u64, unit: ProgressUnit) -> Self {
        Self {
            phase,
            current,
            total: None,
            unit,
        }
    }

    /// Creates a completed progress event.
    pub fn completed() -> Self {
        Self {
            phase: ProgressPhase::Completed,
            current: 1,
            total: Some(1),
            unit: ProgressUnit::None,
        }
    }

    /// Returns the percentage when a valid total is available.
    pub fn percentage(&self) -> Option<u8> {
        let total = self.total?;

        if total == 0 {
            return None;
        }

        let percentage = self.current.saturating_mul(100) / total;

        Some(percentage.min(100) as u8)
    }
}

/// Receives progress events from forensic operations.
///
/// The core filesystem implementations only emit events through this
/// abstraction. They do not know whether the events will be rendered by
/// a terminal, TUI, log, test, or another frontend.
pub trait ProgressReporter: Send + Sync {
    /// Reports a progress event.
    fn report(&self, event: ProgressEvent);
}

/// A progress reporter that intentionally ignores all events.
///
/// This is useful when progress reporting is not required, such as in
/// tests or callers that do not provide a frontend.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProgress;

impl ProgressReporter for NoProgress {
    fn report(&self, _event: ProgressEvent) {}
}

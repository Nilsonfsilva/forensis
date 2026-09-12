//! Filesystem-independent forensic recovery layer.
//!
//! Recovery operates on the common forensic model produced by
//! filesystem parsers.
//!
//! This module must not depend on NTFS, EXT4, FAT32 or any other
//! filesystem-specific structure.

pub mod engine;
pub mod result;

pub use engine::{PhysicalRecoveryEngine, RecoveryEngine};

pub use result::RecoveryResult;

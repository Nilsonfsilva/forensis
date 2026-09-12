//! Fundamental types shared across the entire Forensis project.
//!
//! These strong types replace raw integer values in order to improve
//! readability, type safety, and API consistency.

use std::fmt;

/// Represents an absolute byte offset within a storage device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteOffset(pub u64);

impl ByteOffset {
    /// Zero byte offset.
    pub const ZERO: Self = Self(0);

    /// Creates a new byte offset.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ByteOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} B", self.0)
    }
}

/// Represents a logical sector number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sector(pub u64);

impl Sector {
    /// Sector zero.
    pub const ZERO: Self = Self(0);

    /// Creates a new sector.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Sector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sector({})", self.0)
    }
}

/// Represents a filesystem cluster number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cluster(pub u64);

impl Cluster {
    /// Cluster zero.
    pub const ZERO: Self = Self(0);

    /// Creates a new cluster.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cluster({})", self.0)
    }
}

/// Represents a size expressed in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Zero-byte size.
    pub const ZERO: Self = Self(0);

    /// Creates a new byte size.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} B", self.0)
    }
}

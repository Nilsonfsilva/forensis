use thiserror::Error;

/// Error type used throughout the Forensis project.
#[derive(Debug, Error)]
pub enum ForensisError {
    /// Input/output error (file, disk, device, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The filesystem could not be identified.
    #[error("Unknown filesystem")]
    UnknownFileSystem,

    /// The filesystem was identified but is not supported yet.
    #[error("Unsupported filesystem")]
    UnsupportedFileSystem,

    /// The partition structure is invalid or corrupted.
    #[error("Invalid partition")]
    InvalidPartition,

    /// The boot sector is invalid or does not match the expected format.
    #[error("Invalid boot sector")]
    InvalidBootSector,

    /// The requested file was not found.
    #[error("File not found")]
    FileNotFound,

    /// The requested directory was not found.
    #[error("Directory not found")]
    DirectoryNotFound,

    /// Generic Forensis error.
    #[error("{0}")]
    Generic(String),

    /// Invalid on-disk structure or corrupted data.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

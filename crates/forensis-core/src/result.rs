use crate::error::ForensisError;

/// Standard return type used across the whole project.
pub type Result<T> = std::result::Result<T, ForensisError>;

use crate::error::ForensisError;
use crate::result::Result;

/// Represents an NTFS $LogFile restart area.
///
/// The restart area contains information needed by NTFS
/// to recover unfinished transactions.
#[derive(Debug, Clone)]
pub struct RestartArea {
    /// Major version.
    pub major_version: u16,

    /// Minor version.
    pub minor_version: u16,

    /// Offset of the first log record.
    pub first_log_record: u64,

    /// Current LSN (Log Sequence Number).
    pub current_lsn: u64,
}

/// Represents an NTFS log record.
///
/// A log record stores one filesystem operation.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Log sequence number.
    pub lsn: u64,

    /// Transaction identifier.
    pub transaction_id: u32,

    /// Raw record data.
    pub data: Vec<u8>,
}

/// NTFS transaction journal.
///
/// This represents the $LogFile metadata stream.
#[derive(Debug, Clone)]
pub struct LogFile {
    restart_area: Option<RestartArea>,
    records: Vec<LogRecord>,
}

impl LogFile {
    /// Parses a raw NTFS $LogFile stream.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat("Empty $LogFile".to_string()));
        }

        //
        // First implementation:
        // only validates the stream.
        //
        // Full NTFS restart-area parsing
        // will be added later.
        //

        Ok(Self {
            restart_area: None,
            records: Vec::new(),
        })
    }

    /// Returns restart information.
    pub fn restart_area(&self) -> Option<&RestartArea> {
        self.restart_area.as_ref()
    }

    /// Returns parsed log records.
    pub fn records(&self) -> &[LogRecord] {
        &self.records
    }
}

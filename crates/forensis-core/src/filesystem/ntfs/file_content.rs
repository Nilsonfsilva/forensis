use crate::error::ForensisError;
use crate::result::Result;
use crate::traits::Readable;

use super::data_run_reader::DataRunReader;
use super::parsed_record::ParsedMftRecord;

/// Reads the real content of a file represented by
/// an already parsed NTFS MFT record.
///
/// This layer does not interpret NTFS structures itself.
/// It consumes the `$DATA` attribute already parsed by
/// `MftParser` and delegates physical cluster reading
/// to `DataRunReader`.
pub struct FileContentReader {
    data_run_reader: DataRunReader,
}

impl FileContentReader {
    /// Creates a file-content reader for an NTFS volume.
    ///
    /// `partition_offset` is the byte offset at which the
    /// NTFS filesystem begins in the image.
    ///
    /// `bytes_per_cluster` comes directly from the NTFS
    /// boot sector.
    pub fn new(partition_offset: u64, bytes_per_cluster: u64) -> Self {
        Self {
            data_run_reader: DataRunReader::new(partition_offset, bytes_per_cluster),
        }
    }

    /// Reads the complete content of a parsed MFT record.
    ///
    /// The MFT record must contain a `$DATA` attribute.
    ///
    /// Resident data is returned directly from the
    /// attribute.
    ///
    /// Non-resident data is reconstructed from the
    /// NTFS data runs through `DataRunReader`.
    pub fn read_record<R: Readable>(
        &self,
        reader: &mut R,
        record: &ParsedMftRecord,
    ) -> Result<Vec<u8>> {
        let data = record.data.as_ref().ok_or_else(|| {
            ForensisError::InvalidFormat("MFT record does not contain a DATA attribute".to_string())
        })?;

        self.data_run_reader.read_attribute(reader, data)
    }

    /// Reads the complete content of a parsed DATA attribute.
    ///
    /// This method is useful when the caller already has
    /// the DATA attribute and does not need the complete
    /// MFT record.
    pub fn read_attribute<R: Readable>(
        &self,
        reader: &mut R,
        data: &super::data_attribute::DataAttribute,
    ) -> Result<Vec<u8>> {
        self.data_run_reader.read_attribute(reader, data)
    }
}

use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

use super::mft_record::MftRecord;

/// Reads MFT records from an NTFS partition.
pub struct NtfsMftReader {
    partition_offset: u64,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mft_cluster: u64,
    mft_record_size: u64,
}

impl NtfsMftReader {
    /// Creates a new MFT reader.
    pub fn new(
        partition_offset: u64,
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        mft_cluster: u64,
        mft_record_size: u64,
    ) -> Self {
        Self {
            partition_offset,
            bytes_per_sector,
            sectors_per_cluster,
            mft_cluster,
            mft_record_size,
        }
    }

    /// Computes the byte offset where the MFT starts.
    fn mft_offset(&self) -> u64 {
        self.partition_offset
            + self.mft_cluster * self.sectors_per_cluster as u64 * self.bytes_per_sector as u64
    }

    /// Reads one MFT record using the size defined by the NTFS boot sector.
    pub fn read_record<R: Readable>(&self, reader: &mut R, index: u64) -> Result<MftRecord> {
        let mft_start = self.mft_offset();

        let offset = mft_start
            + index.checked_mul(self.mft_record_size).ok_or_else(|| {
                crate::error::ForensisError::InvalidFormat("MFT record offset overflow".to_string())
            })?;

        let record_size = usize::try_from(self.mft_record_size).map_err(|_| {
            crate::error::ForensisError::InvalidFormat(
                "MFT record size does not fit in memory".to_string(),
            )
        })?;

        if record_size == 0 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Invalid MFT record size".to_string(),
            ));
        }

        let mut buffer = vec![0u8; record_size];

        reader.read_at(ByteOffset::new(offset), &mut buffer)?;

        MftRecord::new(index, buffer)
    }

    /// Reads multiple consecutive MFT records.
    ///
    /// Records are returned in MFT order, starting at `start_index`.
    pub fn read_records<R: Readable>(
        &self,
        reader: &mut R,
        start_index: u64,
        count: u64,
    ) -> Result<Vec<MftRecord>> {
        let end = start_index.checked_add(count).ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat("MFT record range overflow".to_string())
        })?;

        let mut records = Vec::with_capacity(count as usize);

        for index in start_index..end {
            records.push(self.read_record(reader, index)?);
        }

        Ok(records)
    }
}

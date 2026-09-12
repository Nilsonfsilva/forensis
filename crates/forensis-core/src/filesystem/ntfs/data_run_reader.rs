use crate::error::ForensisError;
use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

use super::data_attribute::DataAttribute;
use super::data_run::DataRun;

/// Reads the physical clusters described by NTFS data runs.
pub struct DataRunReader {
    partition_offset: u64,
    bytes_per_cluster: u64,
}

impl DataRunReader {
    /// Creates a new data-run reader.
    pub fn new(partition_offset: u64, bytes_per_cluster: u64) -> Self {
        Self {
            partition_offset,
            bytes_per_cluster,
        }
    }

    /// Returns the physical byte offset of an LCN.
    pub fn lcn_offset(&self, lcn: i64) -> u64 {
        self.partition_offset + lcn as u64 * self.bytes_per_cluster
    }

    /// Reads one data run.
    ///
    /// A run with `Some(lcn)` is physically allocated
    /// and is read from the image.
    ///
    /// A run with `None` is sparse. Sparse clusters have
    /// no physical location and therefore read as zero bytes.
    pub fn read_run<R: Readable>(&self, reader: &mut R, run: &DataRun) -> Result<Vec<u8>> {
        let size = run
            .cluster_count
            .checked_mul(self.bytes_per_cluster)
            .ok_or_else(|| ForensisError::InvalidFormat("Data run size overflow".to_string()))?;

        /*
         * ---------------------------------------------------------
         * SPARSE RUN
         * ---------------------------------------------------------
         *
         * A sparse run has no physical LCN.
         *
         * NTFS represents these clusters logically as zero-filled
         * data. Therefore there is nothing to read from the image.
         */
        let lcn = match run.lcn {
            Some(lcn) => lcn,

            None => {
                return Ok(vec![0u8; size as usize]);
            }
        };

        if lcn < 0 {
            return Err(ForensisError::InvalidFormat(
                "Invalid negative NTFS LCN".to_string(),
            ));
        }

        let offset = self.lcn_offset(lcn);

        let mut buffer = vec![0u8; size as usize];

        reader.read_at(ByteOffset::new(offset), &mut buffer)?;

        Ok(buffer)
    }

    /// Reads all data runs and returns only the
    /// number of bytes specified by the real file size.
    pub fn read_runs(
        &self,
        reader: &mut impl Readable,
        runs: &[DataRun],
        real_size: u64,
    ) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        if real_size == 0 {
            return Ok(result);
        }

        for run in runs {
            if result.len() as u64 >= real_size {
                break;
            }

            let data = self.read_run(reader, run)?;

            let remaining = real_size - result.len() as u64;

            let bytes_to_copy = std::cmp::min(remaining as usize, data.len());

            result.extend_from_slice(&data[..bytes_to_copy]);
        }

        if (result.len() as u64) < real_size {
            return Err(ForensisError::InvalidFormat(
                "Data runs do not contain enough data for file size".to_string(),
            ));
        }

        Ok(result)
    }

    /// Reads the complete content represented by a
    /// parsed NTFS $DATA attribute.
    ///
    /// Resident attributes already contain their data
    /// inside the MFT record.
    ///
    /// Non-resident attributes require reading the
    /// physical clusters described by the data runs.
    pub fn read_attribute(
        &self,
        reader: &mut impl Readable,
        attribute: &DataAttribute,
    ) -> Result<Vec<u8>> {
        if !attribute.non_resident {
            return Ok(attribute.resident_data.clone().unwrap_or_default());
        }

        self.read_runs(reader, &attribute.data_runs, attribute.real_size)
    }
}

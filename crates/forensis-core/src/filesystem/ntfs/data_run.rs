use crate::error::ForensisError;
use crate::result::Result;

/// Represents one NTFS data run.
///
/// A data run describes a contiguous sequence of clusters
/// belonging to a non-resident NTFS attribute.
///
/// `None` represents a sparse run. Sparse runs have no
/// physical LCN and logically contain zero-filled data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    /// Logical Cluster Number (LCN) where the run starts.
    ///
    /// `None` means that this is a sparse run.
    pub lcn: Option<i64>,

    /// Number of clusters contained in the run.
    pub cluster_count: u64,
}

impl DataRun {
    /// Parses an NTFS data-run list.
    ///
    /// The runlist is encoded as a sequence of variable-length
    /// records terminated by 0x00.
    ///
    /// Each record contains:
    ///
    /// - high nibble -> size of the LCN offset
    /// - low nibble  -> size of the cluster count
    ///
    /// The LCN offset is relative to the LCN of the previous run.
    pub fn parse(data: &[u8]) -> Result<Vec<Self>> {
        let mut runs = Vec::new();

        let mut offset = 0usize;

        let mut previous_lcn = 0i64;

        /*
         * The runlist is valid only when an explicit 0x00
         * terminator is encountered.
         */
        let mut terminated = false;

        while offset < data.len() {
            let header = data[offset];

            offset += 1;

            /*
             * 0x00 terminates the runlist.
             */
            if header == 0 {
                terminated = true;
                break;
            }

            let lcn_size = (header >> 4) as usize;

            let cluster_count_size = (header & 0x0F) as usize;

            /*
             * The cluster count must always be present.
             *
             * lcn_size == 0 is valid NTFS syntax and represents
             * a sparse run.
             */
            if cluster_count_size == 0 {
                return Err(ForensisError::InvalidFormat(format!(
                    "Invalid NTFS data run header: 0x{:02X} at offset {}",
                    header,
                    offset - 1
                )));
            }

            let required = cluster_count_size.checked_add(lcn_size).ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid NTFS data run size".to_string())
            })?;

            if offset
                .checked_add(required)
                .is_none_or(|end| end > data.len())
            {
                return Err(ForensisError::InvalidFormat(format!(
                    "Truncated NTFS data run at offset {}",
                    offset - 1
                )));
            }

            /*
             * Read cluster count.
             *
             * This value is unsigned.
             */
            let mut cluster_count = 0u64;

            for i in 0..cluster_count_size {
                cluster_count |= (data[offset + i] as u64) << (i * 8);
            }

            offset += cluster_count_size;

            if cluster_count == 0 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid NTFS data run cluster count".to_string(),
                ));
            }

            /*
             * Sparse run.
             *
             * There is no LCN stored in the runlist.
             * The corresponding clusters are logically zero-filled.
             */
            if lcn_size == 0 {
                runs.push(Self {
                    lcn: None,
                    cluster_count,
                });

                continue;
            }

            /*
             * Read the relative LCN offset.
             *
             * NTFS stores this value as a signed little-endian
             * integer using exactly lcn_size bytes.
             *
             * We first construct the unsigned bit pattern and
             * then perform explicit sign extension.
             */
            let lcn_bits = lcn_size.checked_mul(8).ok_or_else(|| {
                ForensisError::InvalidFormat("Invalid NTFS data run LCN size".to_string())
            })?;

            if lcn_bits > 64 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid NTFS data run LCN size".to_string(),
                ));
            }

            let mut lcn_delta_bits = 0u64;

            for i in 0..lcn_size {
                lcn_delta_bits |= (data[offset + i] as u64) << (i * 8);
            }

            /*
             * Convert the encoded two's-complement bit pattern
             * into a signed i64 value.
             */
            let lcn_delta = if lcn_bits == 64 {
                lcn_delta_bits as i64
            } else {
                let sign_bit = 1u64 << (lcn_bits - 1);

                if lcn_delta_bits & sign_bit != 0 {
                    let extension_mask = !0u64 << lcn_bits;

                    (lcn_delta_bits | extension_mask) as i64
                } else {
                    lcn_delta_bits as i64
                }
            };

            offset += lcn_size;

            /*
             * The LCN is relative to the previous physical LCN.
             *
             * Sparse runs do not change previous_lcn because they
             * do not contain a physical LCN.
             */
            let lcn = previous_lcn.checked_add(lcn_delta).ok_or_else(|| {
                ForensisError::InvalidFormat("NTFS data run LCN overflow".to_string())
            })?;

            /*
             * A physical LCN cannot be negative.
             */
            if lcn < 0 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid negative NTFS LCN".to_string(),
                ));
            }

            runs.push(Self {
                lcn: Some(lcn),
                cluster_count,
            });

            previous_lcn = lcn;
        }

        /*
         * A runlist must end with the NTFS 0x00 terminator.
         *
         * Reaching the end of the supplied buffer without
         * encountering the terminator means the runlist is
         * truncated.
         */
        if !terminated {
            return Err(ForensisError::InvalidFormat(
                "NTFS data runlist is not terminated".to_string(),
            ));
        }

        Ok(runs)
    }
}

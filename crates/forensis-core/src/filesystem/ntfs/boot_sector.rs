use crate::filesystem::FileSystemType;
use crate::result::Result;
use crate::traits::Readable;
use crate::types::ByteOffset;

use super::{
    DataRunReader, FileContentReader, Investigation, MftParser, MftRecord, ParsedMftRecord,
};

/// NTFS boot sector information.
#[derive(Debug, Clone)]
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_cluster: u64,
    pub mft_mirror_cluster: u64,
    pub mft_record_size: u64,
    pub index_record_size: u64,
}

impl NtfsBootSector {
    /// Returns the number of bytes in one cluster.
    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }
}

/// NTFS filesystem implementation.
pub struct NtfsFileSystem {
    pub boot_sector: NtfsBootSector,
    pub partition_offset: u64,
}

impl NtfsFileSystem {
    /// Parses the NTFS boot sector at the given partition offset.
    pub fn parse<R: Readable>(reader: &mut R, partition_offset: u64) -> Result<Self> {
        let mut sector = vec![0u8; 512];

        reader.read_at(ByteOffset(partition_offset), &mut sector)?;

        if &sector[3..7] != b"NTFS" {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Invalid NTFS boot sector signature".to_string(),
            ));
        }

        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        let sectors_per_cluster = sector[13];

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Invalid NTFS sector or cluster geometry".to_string(),
            ));
        }

        let total_sectors = u64::from_le_bytes([
            sector[40], sector[41], sector[42], sector[43], sector[44], sector[45], sector[46],
            sector[47],
        ]);

        let mft_cluster = u64::from_le_bytes([
            sector[48], sector[49], sector[50], sector[51], sector[52], sector[53], sector[54],
            sector[55],
        ]);

        let mft_mirror_cluster = u64::from_le_bytes([
            sector[56], sector[57], sector[58], sector[59], sector[60], sector[61], sector[62],
            sector[63],
        ]);

        let clusters_per_record = sector[64] as i8;

        let cluster_size = bytes_per_sector as u64 * sectors_per_cluster as u64;

        let mft_record_size = if clusters_per_record > 0 {
            cluster_size
                .checked_mul(clusters_per_record as u64)
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "NTFS MFT record size overflow".to_string(),
                    )
                })?
        } else {
            1u64.checked_shl((-clusters_per_record) as u32)
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "Invalid NTFS MFT record size".to_string(),
                    )
                })?
        };

        let clusters_per_index_record = sector[68] as i8;

        let index_record_size = if clusters_per_index_record > 0 {
            cluster_size
                .checked_mul(clusters_per_index_record as u64)
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "NTFS index record size overflow".to_string(),
                    )
                })?
        } else {
            1u64.checked_shl((-clusters_per_index_record) as u32)
                .ok_or_else(|| {
                    crate::error::ForensisError::InvalidFormat(
                        "Invalid NTFS index record size".to_string(),
                    )
                })?
        };

        if total_sectors == 0 || mft_record_size == 0 || index_record_size == 0 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "Invalid NTFS filesystem geometry".to_string(),
            ));
        }

        Ok(Self {
            boot_sector: NtfsBootSector {
                bytes_per_sector,
                sectors_per_cluster,
                total_sectors,
                mft_cluster,
                mft_mirror_cluster,
                mft_record_size,
                index_record_size,
            },
            partition_offset,
        })
    }

    /// Reads the content of a file represented by an NTFS data attribute.
    pub fn read_file_content<R: Readable>(
        &self,
        reader: &mut R,
        attribute: &super::data_attribute::DataAttribute,
    ) -> Result<Vec<u8>> {
        let file_content_reader =
            FileContentReader::new(self.partition_offset, self.boot_sector.bytes_per_cluster());

        file_content_reader.read_attribute(reader, attribute)
    }

    /// Parses the NTFS MFT and builds an investigation model.
    pub fn investigate<R: Readable>(&self, reader: &mut R) -> Result<Investigation> {
        /*
         * ---------------------------------------------------------
         * 1. Create the MFT reader.
         * ---------------------------------------------------------
         */

        let mft_reader = super::NtfsMftReader::new(
            self.partition_offset,
            self.boot_sector.bytes_per_sector,
            self.boot_sector.sectors_per_cluster,
            self.boot_sector.mft_cluster,
            self.boot_sector.mft_record_size,
        );

        /*
         * ---------------------------------------------------------
         * 2. Read MFT record 0.
         * ---------------------------------------------------------
         */

        let mut record_zero = mft_reader.read_record(reader, 0)?;

        /*
         * ---------------------------------------------------------
         * 3. Parse record 0.
         * ---------------------------------------------------------
         */

        MftParser::parse(&mut record_zero)?;

        /*
         * ---------------------------------------------------------
         * 4. Locate the DATA attribute of $MFT.
         * ---------------------------------------------------------
         */

        let parsed_record_zero: ParsedMftRecord = MftParser::parse(&mut record_zero)?;

        let data = parsed_record_zero.data.as_ref().ok_or_else(|| {
            crate::error::ForensisError::InvalidFormat("$MFT DATA attribute not found".to_string())
        })?;

        /*
         * ---------------------------------------------------------
         * 5. The $MFT DATA attribute must be non-resident.
         * ---------------------------------------------------------
         */

        if !data.non_resident {
            return Err(crate::error::ForensisError::InvalidFormat(
                "$MFT DATA attribute is resident".to_string(),
            ));
        }

        /*
         * ---------------------------------------------------------
         * 6. Determine the logical size of the MFT.
         * ---------------------------------------------------------
         */

        let mft_size = data.real_size;

        if mft_size == 0 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "$MFT has zero logical size".to_string(),
            ));
        }

        let record_size = self.boot_sector.mft_record_size;

        if record_size == 0 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "MFT record size is zero".to_string(),
            ));
        }

        if mft_size % record_size != 0 {
            return Err(crate::error::ForensisError::InvalidFormat(
                "MFT logical size is not aligned to record size".to_string(),
            ));
        }

        let record_count = mft_size / record_size;

        /*
         * ---------------------------------------------------------
         * 7. Reconstruct the logical MFT stream from its DATA runs.
         * ---------------------------------------------------------
         */

        let data_run_reader =
            DataRunReader::new(self.partition_offset, self.boot_sector.bytes_per_cluster());

        let mft_bytes = data_run_reader.read_runs(reader, &data.data_runs, mft_size)?;

        /*
         * ---------------------------------------------------------
         * 8. Create the investigation.
         * ---------------------------------------------------------
         */

        let mut investigation = Investigation::new(self.boot_sector.sectors_per_cluster as u64);

        /*
         * ---------------------------------------------------------
         * 9. Process every MFT record.
         *
         * A completely zero-filled slot does not represent an MFT
         * record and is therefore skipped.
         * ---------------------------------------------------------
         */

        for index in 0..record_count {
            let offset = index.checked_mul(record_size).ok_or_else(|| {
                crate::error::ForensisError::InvalidFormat("MFT record offset overflow".to_string())
            })?;

            let end = offset.checked_add(record_size).ok_or_else(|| {
                crate::error::ForensisError::InvalidFormat("MFT record end overflow".to_string())
            })?;

            if end as usize > mft_bytes.len() {
                return Err(crate::error::ForensisError::InvalidFormat(
                    "MFT record exceeds reconstructed MFT data".to_string(),
                ));
            }

            let record_bytes = mft_bytes[offset as usize..end as usize].to_vec();

            /*
             * -----------------------------------------------------
             * Empty MFT slot.
             *
             * The complete slot is zero-filled, so it does not
             * represent an MFT record.
             * -----------------------------------------------------
             */

            if record_bytes.iter().all(|&byte| byte == 0) {
                continue;
            }

            let mut record = MftRecord::new(index, record_bytes)?;

            investigation.process_mft_record(&mut record)?;
        }

        Ok(investigation)
    }
}

impl crate::filesystem::FileSystem for NtfsFileSystem {
    fn filesystem_type(&self) -> FileSystemType {
        FileSystemType::Ntfs
    }

    fn list_files(&self) -> Vec<String> {
        Vec::new()
    }

    fn metadata(&self) -> String {
        format!(
            "NTFS MFT cluster: {}, \
             MFT mirror cluster: {}, \
             MFT record size: {} bytes, \
             index record size: {} bytes",
            self.boot_sector.mft_cluster,
            self.boot_sector.mft_mirror_cluster,
            self.boot_sector.mft_record_size,
            self.boot_sector.index_record_size,
        )
    }
}

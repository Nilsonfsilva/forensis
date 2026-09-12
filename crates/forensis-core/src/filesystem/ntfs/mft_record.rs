use crate::error::ForensisError;
use crate::result::Result;

/// Signature expected at the beginning of every valid MFT record.
pub const MFT_SIGNATURE: &[u8; 4] = b"FILE";

/// NTFS sector size used by the Update Sequence Array mechanism.
const NTFS_SECTOR_SIZE: usize = 512;

/// Header of an NTFS MFT record.
#[derive(Debug, Clone)]
pub struct MftRecordHeader {
    /// Update Sequence Array offset.
    pub usa_offset: u16,

    /// Number of Update Sequence Array entries.
    pub usa_count: u16,

    /// Record sequence number.
    pub sequence_number: u16,

    /// Number of hard links.
    pub hard_link_count: u16,

    /// Offset to the first attribute.
    pub first_attribute_offset: u16,

    /// Record flags.
    pub flags: u16,

    /// Bytes currently used by this record.
    pub used_size: u32,

    /// Allocated record size.
    pub allocated_size: u32,

    /// Base record reference.
    pub base_record: u64,

    /// Next available attribute identifier.
    pub next_attribute_id: u16,
}

/// Represents one logical NTFS MFT record.
///
/// The record size is determined by the NTFS boot sector.
///
/// NTFS stores Update Sequence Number values in the sector
/// trailers of MFT records. Those values are replaced with
/// the original trailer bytes from the Update Sequence Array
/// before the record is parsed.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// Record number inside the Master File Table.
    pub index: u64,

    /// Parsed record header.
    pub header: Option<MftRecordHeader>,

    /// MFT record bytes after USA fixup.
    data: Vec<u8>,
}

impl MftRecord {
    /// Creates a new MFT record after validating its size,
    /// signature, and Update Sequence Array fixup.
    pub fn new(index: u64, mut data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return Err(ForensisError::InvalidFormat("Empty MFT record".to_string()));
        }

        if data.len() < 4 {
            return Err(ForensisError::InvalidFormat(
                "MFT record is smaller than its signature".to_string(),
            ));
        }

        if &data[0..4] != MFT_SIGNATURE {
            return Err(ForensisError::InvalidFormat(
                "Invalid MFT record signature".to_string(),
            ));
        }

        Self::apply_usa_fixup(&mut data)?;

        Ok(Self {
            index,
            header: None,
            data,
        })
    }

    /// Applies the NTFS Update Sequence Array fixup to an MFT record.
    ///
    /// Each sector covered by the record stores the Update Sequence
    /// Number in its final two bytes. The original two bytes for
    /// each sector are stored in the Update Sequence Array.
    fn apply_usa_fixup(data: &mut [u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(ForensisError::InvalidFormat(
                "MFT record is too small for Update Sequence Array".to_string(),
            ));
        }

        let usa_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
        let usa_count = u16::from_le_bytes([data[6], data[7]]) as usize;

        if usa_count < 2 {
            return Err(ForensisError::InvalidFormat(
                "Invalid MFT record USA count".to_string(),
            ));
        }

        let usa_size = usa_count.checked_mul(2).ok_or_else(|| {
            ForensisError::InvalidFormat("MFT record USA size overflow".to_string())
        })?;

        let usa_end = usa_offset.checked_add(usa_size).ok_or_else(|| {
            ForensisError::InvalidFormat("MFT record USA range overflow".to_string())
        })?;

        if usa_offset < 8 || usa_end > data.len() {
            return Err(ForensisError::InvalidFormat(
                "MFT record USA exceeds record".to_string(),
            ));
        }

        if data.len() % NTFS_SECTOR_SIZE != 0 {
            return Err(ForensisError::InvalidFormat(
                "MFT record size is not aligned to the NTFS sector size".to_string(),
            ));
        }

        let sector_count = data.len() / NTFS_SECTOR_SIZE;

        if usa_count != sector_count + 1 {
            return Err(ForensisError::InvalidFormat(
                "MFT record USA count does not match the number of sectors".to_string(),
            ));
        }

        let update_sequence = u16::from_le_bytes([data[usa_offset], data[usa_offset + 1]]);

        for sector_index in 0..sector_count {
            let replacement_offset = usa_offset + 2 + sector_index * 2;

            let replacement = [data[replacement_offset], data[replacement_offset + 1]];

            let trailer_offset = (sector_index + 1) * NTFS_SECTOR_SIZE - 2;

            let trailer = u16::from_le_bytes([data[trailer_offset], data[trailer_offset + 1]]);

            if trailer != update_sequence {
                return Err(ForensisError::InvalidFormat(
                    "MFT record USA sequence mismatch".to_string(),
                ));
            }

            data[trailer_offset..trailer_offset + 2].copy_from_slice(&replacement);
        }

        Ok(())
    }

    /// Returns the record signature.
    pub fn signature(&self) -> &[u8] {
        &self.data[0..4]
    }

    /// Returns the logical record bytes after USA fixup.
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Returns the size of this MFT record in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the record contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the parsed header, if available.
    pub fn header(&self) -> Option<&MftRecordHeader> {
        self.header.as_ref()
    }

    /// Stores the parsed header.
    pub fn set_header(&mut self, header: MftRecordHeader) {
        self.header = Some(header);
    }
}

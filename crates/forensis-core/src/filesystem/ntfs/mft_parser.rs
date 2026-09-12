use crate::error::ForensisError;
use crate::result::Result;

use super::{DataAttribute, IndexRoot, MftRecord, ParsedMftRecord};

use super::mft_record::MftRecordHeader;

use super::mft_attribute::{AttributeType, MftAttribute};

use super::file_name::FileNameAttribute;
use super::standard_information::StandardInformation;

/// Parses NTFS MFT records.
pub struct MftParser;

impl MftParser {
    /// Parses one raw MFT record into a structured representation.
    pub fn parse(record: &mut MftRecord) -> Result<ParsedMftRecord> {
        /*
         * ---------------------------------------------------------
         * MFT RECORD HEADER
         * ---------------------------------------------------------
         */

        {
            let data = record.raw();

            if data.len() < 42 {
                return Err(ForensisError::InvalidFormat(
                    "Invalid MFT record".to_string(),
                ));
            }

            let usa_offset = u16::from_le_bytes([data[4], data[5]]);
            let usa_count = u16::from_le_bytes([data[6], data[7]]);

            let sequence_number = u16::from_le_bytes([data[16], data[17]]);

            let hard_link_count = u16::from_le_bytes([data[18], data[19]]);

            let first_attribute_offset = u16::from_le_bytes([data[20], data[21]]);

            let flags = u16::from_le_bytes([data[22], data[23]]);

            let used_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

            let allocated_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

            let base_record = u64::from_le_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]);

            let next_attribute_id = u16::from_le_bytes([data[40], data[41]]);

            let header = MftRecordHeader {
                usa_offset,
                usa_count,
                sequence_number,
                hard_link_count,
                first_attribute_offset,
                flags,
                used_size,
                allocated_size,
                base_record,
                next_attribute_id,
            };

            if first_attribute_offset as usize >= data.len() {
                return Err(ForensisError::InvalidFormat(
                    "Invalid first attribute offset".to_string(),
                ));
            }

            record.set_header(header);
        }

        /*
         * ---------------------------------------------------------
         * MFT ATTRIBUTES
         * ---------------------------------------------------------
         */

        let data = record.raw();

        let header = record.header().ok_or_else(|| {
            ForensisError::InvalidFormat("MFT record header not available".to_string())
        })?;

        let first_attribute = header.first_attribute_offset as usize;

        let mft_flags = header.flags;

        let mut offset = first_attribute;

        let mut standard_information = None;
        let mut file_names = Vec::new();
        let mut data_attribute = None;
        let mut index_root = None;

        while offset + 16 <= data.len() {
            /*
             * -----------------------------------------------------
             * END OF ATTRIBUTES
             * -----------------------------------------------------
             *
             * The terminator 0xFFFFFFFF occupies the first four
             * bytes of the attribute.
             */

            let attribute_type_raw = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            if attribute_type_raw == 0xFFFFFFFF {
                if record.index == 65 {}

                break;
            }

            /*
             * -----------------------------------------------------
             * COMMON ATTRIBUTE HEADER
             * -----------------------------------------------------
             *
             * The common header contains at least 16 bytes.
             */

            let declared_length = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            let remaining = data.len() - offset;

            if declared_length > remaining {
                return Err(ForensisError::InvalidFormat(
                    "MFT attribute exceeds record".to_string(),
                ));
            }

            let attribute = MftAttribute::parse(&data[offset..])?;

            if attribute.attribute_type == AttributeType::End {
                break;
            }

            if attribute.length == 0 {
                break;
            }

            let attribute_length = attribute.length as usize;

            /*
             * The complete attribute must remain inside the record.
             */

            let attribute_end = offset.checked_add(attribute_length).ok_or_else(|| {
                ForensisError::InvalidFormat("MFT attribute length overflow".to_string())
            })?;

            if attribute_end > data.len() {
                return Err(ForensisError::InvalidFormat(
                    "MFT attribute exceeds record".to_string(),
                ));
            }

            /*
             * -----------------------------------------------------
             * ATTRIBUTE TYPE
             * -----------------------------------------------------
             *
             * Only now is the specific attribute content interpreted.
             *
             * Unknown attributes are deliberately ignored.
             * This allows the parser to continue investigating
             * the remaining record when it encounters NTFS
             * attributes that are not yet implemented by Forensis.
             */

            match attribute.attribute_type {
                AttributeType::StandardInformation => {
                    standard_information = StandardInformation::parse(&attribute.data).ok();
                }

                AttributeType::FileName => {
                    let name = FileNameAttribute::parse_value(&attribute.data)?;

                    file_names.push(name);
                }

                AttributeType::Data => {
                    let attribute_bytes = &data[offset..attribute_end];

                    data_attribute = Some(DataAttribute::parse(attribute_bytes)?);
                }

                AttributeType::IndexRoot => {
                    index_root = Some(IndexRoot::parse(&attribute.data)?);
                }

                /*
                 * Any attribute without a specific parser is ignored.
                 */
                _ => {}
            }

            /*
             * Advance exactly by the length declared by the attribute.
             *
             * Never advance according to the size of the interpreted
             * content.
             */

            offset = attribute_end;
        }

        Ok(ParsedMftRecord {
            index: record.index,
            mft_flags,
            standard_information,
            file_names,
            data: data_attribute,
            index_root,
        })
    }
}

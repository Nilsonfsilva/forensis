use std::path::{Path, PathBuf};

use forensis_core::{
    disk::ImageReader,
    filesystem::{FileSystemDetector, FileSystemType},
    forensic::{ForensicModel, ForensicTree},
    Partition, PartitionTableDetector, PartitionTableReader, PartitionTableType, Readable,
};

use forensis_core::result::Result;

/// Investigates one filesystem and produces its
/// filesystem-independent forensic model and tree.
///
/// This is the single point where the application knows that a
/// filesystem implementation exists. Every supported filesystem
/// keeps its own internal investigation result and converts it
/// into the common `ForensicModel`.
///
/// `partition` is used when the filesystem belongs to a partition
/// of a partition table. `offset` is used when the image itself
/// is a whole filesystem without a partition table.
fn inspect_filesystem<R: Readable>(
    filesystem: FileSystemType,
    reader: &mut R,
    partition: Option<&Partition>,
    offset: u64,
    image_source: Option<String>,
) -> Result<(Option<ForensicModel>, Option<ForensicTree>)> {
    let model: ForensicModel = match filesystem {
        FileSystemType::Ntfs => {
            let ntfs = match partition {
                Some(partition) => FileSystemDetector::open_ntfs(reader, partition)?,
                None => FileSystemDetector::open_ntfs_at(reader, offset)?,
            };

            let investigation = ntfs.investigate(reader)?;

            investigation.to_forensic_model(image_source)
        }

        FileSystemType::Ext4 => {
            let ext4 = match partition {
                Some(partition) => FileSystemDetector::open_ext4(reader, partition)?,
                None => FileSystemDetector::open_ext4_at(reader, offset)?,
            };

            let partition_offset = match partition {
                Some(partition) => partition.start_sector * 512,
                None => offset,
            };

            let mut ext4_reader =
                forensis_core::filesystem::ext4::Ext4Reader::new(&mut *reader, partition_offset);

            let investigation = ext4.investigate(&mut ext4_reader)?;

            investigation.to_forensic_model(image_source)
        }

        FileSystemType::Fat32 => {
            let fat32 = match partition {
                Some(partition) => FileSystemDetector::open_fat32(reader, partition)?,
                None => FileSystemDetector::open_fat32_at(reader, offset)?,
            };

            let partition_offset = match partition {
                Some(partition) => partition.start_sector * 512,
                None => offset,
            };

            let mut fat32_reader =
                forensis_core::filesystem::fat32::Fat32Reader::new(&mut *reader, partition_offset)?;

            let investigation = fat32.investigate(&mut fat32_reader)?;

            investigation.to_forensic_model(image_source)
        }

        FileSystemType::ExFat => {
            let exfat = match partition {
                Some(partition) => FileSystemDetector::open_exfat(reader, partition)?,
                None => FileSystemDetector::open_exfat_at(reader, offset)?,
            };

            let partition_offset = match partition {
                Some(partition) => partition.start_sector * 512,
                None => offset,
            };

            let mut exfat_reader =
                forensis_core::filesystem::exfat::ExFatReader::new(&mut *reader, partition_offset)?;

            let investigation = exfat.investigate(&mut exfat_reader)?;

            investigation.to_forensic_model(image_source)
        }

        /*
         * Unsupported filesystems never reach this helper because
         * detection is always checked with `is_supported()` first.
         */
        _ => return Ok((None, None)),
    };

    let tree = ForensicTree::from_model(&model);

    Ok((Some(model), Some(tree)))
}

#[derive(Debug)]
pub struct InspectionResult {
    pub image: PathBuf,
    pub size: u64,
    pub partition_table: Option<PartitionTableType>,
    pub partitions: Vec<Partition>,
    pub filesystems: Vec<FileSystemType>,

    /// Consolidated forensic model.
    ///
    /// Each item corresponds to a partition/filesystem
    /// that was effectively investigated.
    ///
    /// The application layer does not know the filesystem-
    /// specific internal result.
    pub models: Vec<Option<ForensicModel>>,

    /// Generic evidence tree.
    ///
    /// The tree is built exclusively from the
    /// ForensicModel and does not depend on NTFS, EXT4,
    /// FAT32, exFAT or any other filesystem.
    pub trees: Vec<Option<ForensicTree>>,
}

pub fn inspect_image(path: impl AsRef<Path>) -> Result<InspectionResult> {
    let path = path.as_ref();

    let path_string = path.to_string_lossy();

    let image_source = Some(path_string.to_string());

    let mut reader = ImageReader::open(&path_string)?;

    let size = reader.size().value();

    let table = PartitionTableDetector::parse(&mut reader)?;

    let (partition_table, partitions) = match table {
        Some(table) => {
            let table_type = table.table_type();

            let partitions = table.partitions().to_vec();

            (Some(table_type), partitions)
        }

        None => (None, Vec::new()),
    };

    let mut filesystems = Vec::new();

    let mut models = Vec::new();

    let mut trees = Vec::new();

    /*
     * ---------------------------------------------------------
     * CASE 1:
     *
     * The image contains a partition table.
     *
     * Each partition is investigated independently.
     * ---------------------------------------------------------
     */

    if !partitions.is_empty() {
        for partition in &partitions {
            let partition_offset = match partition.start_sector.checked_mul(512) {
                Some(value) => value,

                None => {
                    filesystems.push(FileSystemType::Unknown);
                    models.push(None);
                    trees.push(None);

                    continue;
                }
            };

            let partition_size = match partition.sector_count.checked_mul(512) {
                Some(value) => value,

                None => {
                    filesystems.push(FileSystemType::Unknown);
                    models.push(None);
                    trees.push(None);

                    continue;
                }
            };

            let partition_end = match partition_offset.checked_add(partition_size) {
                Some(value) => value,

                None => {
                    filesystems.push(FileSystemType::Unknown);
                    models.push(None);
                    trees.push(None);

                    continue;
                }
            };

            /*
             * A partition declaration outside the
             * physical image must not be investigated.
             */

            if partition_end > size {
                filesystems.push(FileSystemType::Unknown);
                models.push(None);
                trees.push(None);

                continue;
            }

            let filesystem = FileSystemDetector::detect(&mut reader, partition)?;

            filesystems.push(filesystem);

            /*
             * -------------------------------------------------
             * Filesystem support boundary.
             *
             * Detection tells us what filesystem exists.
             * Support tells us whether Forensis can currently
             * investigate it.
             *
             * Unsupported filesystems must never reach an
             * unrelated filesystem parser.
             * -------------------------------------------------
             */

            if !filesystem.is_supported() {
                models.push(None);
                trees.push(None);

                continue;
            }

            /*
             * The supported filesystem is opened and investigated
             * inside the common helper. The application only
             * receives the filesystem-independent model and tree.
             */
            let (model, tree) = inspect_filesystem(
                filesystem,
                &mut reader,
                Some(partition),
                0,
                image_source.clone(),
            )?;

            models.push(model);
            trees.push(tree);
        }
    }

    /*
     * ---------------------------------------------------------
     * CASE 2:
     *
     * The image itself is a filesystem.
     *
     * No partition table exists.
     * ---------------------------------------------------------
     */

    if partitions.is_empty() {
        let filesystem = FileSystemDetector::detect_at(&mut reader, 0)?;

        filesystems.push(filesystem);

        /*
         * -----------------------------------------------------
         * Filesystem support boundary.
         *
         * Do not attempt to open a filesystem parser until
         * detection has confirmed that Forensis supports it.
         * -----------------------------------------------------
         */

        if !filesystem.is_supported() {
            models.push(None);
            trees.push(None);
        } else {
            /*
             * The supported whole-image filesystem is investigated
             * by the same common helper used for partitions.
             */
            let (model, tree) =
                inspect_filesystem(filesystem, &mut reader, None, 0, image_source.clone())?;

            models.push(model);
            trees.push(tree);
        }
    }

    Ok(InspectionResult {
        image: path.to_path_buf(),
        size,
        partition_table,
        partitions,
        filesystems,
        models,
        trees,
    })
}

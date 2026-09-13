use forensis_app::inspect_image;

use forensis_core::{
    recovery::{PhysicalRecoveryEngine, RecoveryEngine},
    ForensicStatus,
};

use forensis_core::disk::ImageReader;

#[test]
fn test_recover_deleted_files_from_real_fat32_image() {
    /*
     * ---------------------------------------------------------
     * REAL FAT32 FORENSIC IMAGE
     * ---------------------------------------------------------
     *
     * This image contains deleted FAT32 objects whose residual
     * FAT chain was kept (the classical deletion artifact).
     *
     * The test walks the complete chain:
     *
     * image
     *   -> inspection
     *   -> FAT32 investigation
     *   -> ForensicModel
     *   -> Deleted objects
     *   -> physical regions
     *   -> PhysicalRecoveryEngine
     *   -> recovered bytes
     */

    let image_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../lab/fat32-validation/disk-fat32.img");

    if !image_path.exists() {
        eprintln!(
            "skipping: real FAT32 image not found at {}",
            image_path.display()
        );
        return;
    }

    /*
     * ---------------------------------------------------------
     * OPEN IMAGE
     * ---------------------------------------------------------
     */

    let image_path_string = image_path.to_string_lossy().to_string();

    let mut reader =
        ImageReader::open(&image_path_string).expect("failed to open real FAT32 image");

    /*
     * ---------------------------------------------------------
     * INSPECT IMAGE
     * ---------------------------------------------------------
     *
     * The application runs the complete FAT32 investigation.
     */

    let inspection = inspect_image(&image_path).expect("failed to inspect real FAT32 image");

    assert!(
        !inspection.models.is_empty(),
        "inspection produced no forensic models"
    );

    /*
     * ---------------------------------------------------------
     * DETERMINE PARTITION OFFSET
     * ---------------------------------------------------------
     */

    let partition_offset = inspection
        .partitions
        .first()
        .map(|partition| {
            partition
                .start_sector
                .checked_mul(512)
                .expect("partition offset overflow")
        })
        .unwrap_or(0);

    let engine = PhysicalRecoveryEngine::new(partition_offset, 512);

    /*
     * ---------------------------------------------------------
     * SEARCH DELETED FORENSIC OBJECTS
     * ---------------------------------------------------------
     */

    let mut deleted_count = 0usize;

    let mut deleted_with_physical_regions = 0usize;

    let mut recovered_count = 0usize;

    for model in inspection.models.iter().flatten() {
        for entry in model.entries() {
            if entry.identity.status != ForensicStatus::Deleted {
                continue;
            }

            deleted_count += 1;

            println!("\n[DELETED] {}", entry.identity.name);

            println!("  path: {}", entry.identity.path);

            println!("  FAT cluster: {}", entry.identity.object_id);

            println!("  real size: {:?}", entry.metadata.real_size);

            println!("  allocated size: {:?}", entry.metadata.allocated_size);

            println!(
                "  physical regions: {}",
                entry.physical_location.regions.len()
            );

            if entry.physical_location.regions.is_empty() {
                println!("  recovery: no physical regions");

                continue;
            }

            deleted_with_physical_regions += 1;

            /*
             * -------------------------------------------------
             * REAL PHYSICAL RECOVERY
             * -------------------------------------------------
             */

            let result = engine
                .recover(&mut reader, entry)
                .expect("physical recovery failed unexpectedly");

            if result.is_recovered() {
                recovered_count += 1;

                println!("  recovery: SUCCESS");

                println!(
                    "  recovered bytes: {}",
                    result.data().map(|data| data.len()).unwrap_or(0)
                );
            } else {
                println!("  recovery: FAILED");

                println!("  reason: {:?}", result.reason());
            }
        }
    }

    /*
     * ---------------------------------------------------------
     * FORENSIC ASSERTIONS
     * ---------------------------------------------------------
     *
     * The image is known to contain deleted files.
     */

    assert!(
        deleted_count > 0,
        "no deleted forensic objects were found in the real image"
    );

    assert!(
        deleted_with_physical_regions > 0,
        "deleted objects were found, but none has physical recovery regions"
    );

    assert!(
        recovered_count > 0,
        "deleted objects were found, but none could be physically recovered"
    );

    println!("\n==================================================");

    println!("Deleted objects found: {}", deleted_count);

    println!(
        "Deleted objects with physical regions: {}",
        deleted_with_physical_regions
    );

    println!("Deleted objects recovered: {}", recovered_count);

    println!("==================================================");
}

#[test]
fn test_recover_deleted_files_from_fat32_mbr_partition() {
    /*
     * ---------------------------------------------------------
     * REAL FAT32 IMAGE INSIDE AN MBR PARTITION
     * ---------------------------------------------------------
     *
     * The FAT32 volume is wrapped in a partition table at a
     * nonzero sector offset. Physical regions produced by the
     * FAT32 layer are volume-relative; the recovery engine must
     * translate them using the partition offset.
     */

    let image_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../lab/fat32-validation/disk-mbr.img");

    if !image_path.exists() {
        eprintln!(
            "skipping: FAT32 MBR image not found at {}",
            image_path.display()
        );
        return;
    }

    let image_path_string = image_path.to_string_lossy().to_string();

    let mut reader = ImageReader::open(&image_path_string).expect("failed to open FAT32 MBR image");

    let inspection = inspect_image(&image_path).expect("failed to inspect FAT32 MBR image");

    assert_eq!(
        inspection.partitions.len(),
        1,
        "expected exactly one MBR partition"
    );

    let partition = inspection
        .partitions
        .first()
        .expect("partition table should not be empty");

    assert!(
        partition.start_sector > 0,
        "FAT32 partition should start after the MBR"
    );

    let partition_offset = partition
        .start_sector
        .checked_mul(512)
        .expect("partition offset overflow");

    let engine = PhysicalRecoveryEngine::new(partition_offset, 512);

    let mut recovered_count = 0usize;

    for model in inspection.models.iter().flatten() {
        for entry in model.entries() {
            if entry.identity.status != ForensicStatus::Deleted {
                continue;
            }

            if entry.physical_location.regions.is_empty() {
                continue;
            }

            let result = engine
                .recover(&mut reader, entry)
                .expect("physical recovery failed unexpectedly");

            if result.is_recovered() {
                recovered_count += 1;
            }
        }
    }

    assert!(
        recovered_count > 0,
        "no deleted objects were recovered through the MBR partition"
    );

    println!(
        "\nRecovered deleted objects through MBR partition: {}",
        recovered_count
    );
}

#[test]
fn test_recover_deleted_files_from_real_ntfs_image() {
    /*
     * ---------------------------------------------------------
     * REAL NTFS FORENSIC IMAGE
     * ---------------------------------------------------------
     *
     * This image contains deleted and fragmented NTFS objects.
     *
     * The test walks the complete chain:
     *
     * image
     *   -> inspection
     *   -> NTFS investigation
     *   -> ForensicModel
     *   -> Deleted objects
     *   -> physical regions
     *   -> PhysicalRecoveryEngine
     *   -> recovered bytes
     */

    let image_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../lab/ntfs-realistic/disk-fragmented.img");

    if !image_path.exists() {
        eprintln!(
            "skipping: real NTFS image not found at {}",
            image_path.display()
        );
        return;
    }

    /*
     * ---------------------------------------------------------
     * OPEN IMAGE
     * ---------------------------------------------------------
     */

    let image_path_string = image_path.to_string_lossy().to_string();

    let mut reader = ImageReader::open(&image_path_string).expect("failed to open real NTFS image");

    /*
     * ---------------------------------------------------------
     * INSPECT IMAGE
     * ---------------------------------------------------------
     *
     * The application runs the complete NTFS investigation.
     */

    let inspection = inspect_image(&image_path).expect("failed to inspect real NTFS image");

    assert!(
        !inspection.models.is_empty(),
        "inspection produced no forensic models"
    );

    /*
     * ---------------------------------------------------------
     * DETERMINE PARTITION OFFSET
     * ---------------------------------------------------------
     *
     * The physical regions produced by the NTFS layer are
     * relative to the start of the volume.
     *
     * The PhysicalRecoveryEngine transforms:
     *
     *     sector relative to the volume
     *
     * into:
     *
     *     absolute offset inside the image.
     */

    let partition_offset = inspection
        .partitions
        .first()
        .map(|partition| {
            partition
                .start_sector
                .checked_mul(512)
                .expect("partition offset overflow")
        })
        .unwrap_or(0);

    /*
     * In this NTFS image we use physical sectors of 512 bytes.
     */

    let engine = PhysicalRecoveryEngine::new(partition_offset, 512);

    /*
     * ---------------------------------------------------------
     * SEARCH DELETED FORENSIC OBJECTS
     * ---------------------------------------------------------
     */

    let mut deleted_count = 0usize;

    let mut deleted_with_physical_regions = 0usize;

    let mut recovered_count = 0usize;

    for model in inspection.models.iter().flatten() {
        for entry in model.entries() {
            if entry.identity.status != ForensicStatus::Deleted {
                continue;
            }

            deleted_count += 1;

            println!("\n[DELETED] {}", entry.identity.name);

            println!("  path: {}", entry.identity.path);

            println!("  MFT record: {}", entry.identity.object_id);

            println!("  real size: {:?}", entry.metadata.real_size);

            println!("  allocated size: {:?}", entry.metadata.allocated_size);

            println!(
                "  physical regions: {}",
                entry.physical_location.regions.len()
            );

            if entry.physical_location.regions.is_empty() {
                println!("  recovery: no physical regions");

                continue;
            }

            deleted_with_physical_regions += 1;

            /*
             * -------------------------------------------------
             * REAL PHYSICAL RECOVERY
             * -------------------------------------------------
             */

            let result = engine
                .recover(&mut reader, entry)
                .expect("physical recovery failed unexpectedly");

            if result.is_recovered() {
                recovered_count += 1;

                println!("  recovery: SUCCESS");

                println!(
                    "  recovered bytes: {}",
                    result.data().map(|data| data.len()).unwrap_or(0)
                );
            } else {
                println!("  recovery: FAILED");

                println!("  reason: {:?}", result.reason());
            }
        }
    }

    /*
     * ---------------------------------------------------------
     * FORENSIC ASSERTIONS
     * ---------------------------------------------------------
     *
     * The image is known to contain deleted files.
     */

    assert!(
        deleted_count > 0,
        "no deleted forensic objects were found in the real image"
    );

    /*
     * At least one deleted object must have enough physical
     * information to attempt recovery.
     */

    assert!(
        deleted_with_physical_regions > 0,
        "deleted objects were found, but none has physical recovery regions"
    );

    /*
     * At least one deleted object must be physically
     * recoverable.
     */

    assert!(
        recovered_count > 0,
        "deleted objects were found, but none could be physically recovered"
    );

    println!("\n==================================================");

    println!("Deleted objects found: {}", deleted_count);

    println!(
        "Deleted objects with physical regions: {}",
        deleted_with_physical_regions
    );

    println!("Deleted objects recovered: {}", recovered_count);

    println!("==================================================");
}

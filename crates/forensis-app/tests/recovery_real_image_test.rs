use forensis_app::inspect_image;

use forensis_core::{
    recovery::{PhysicalRecoveryEngine, RecoveryEngine},
    ForensicStatus,
};

use forensis_core::disk::ImageReader;

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

    assert!(
        image_path.exists(),
        "Real NTFS image not found: {}",
        image_path.display()
    );

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

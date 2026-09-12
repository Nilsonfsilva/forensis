use forensis_core::forensic::{
    ForensicAllocation, ForensicContentLayout, ForensicContentSegment, ForensicEntry,
    ForensicEntryKind, ForensicFilesystem, ForensicHierarchy, ForensicIdentity, ForensicMetadata,
    ForensicObject, ForensicPhysicalLocation, ForensicPhysicalRegion, ForensicStatus,
};

use forensis_core::recovery::{PhysicalRecoveryEngine, RecoveryEngine};

use forensis_core::result::Result;
use forensis_core::traits::Readable;
use forensis_core::types::{ByteOffset, ByteSize};

struct MemoryReader {
    data: Vec<u8>,
}

impl MemoryReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl Readable for MemoryReader {
    fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
        let start = offset.value() as usize;

        let end = start.checked_add(buffer.len()).ok_or_else(|| {
            forensis_core::ForensisError::InvalidFormat("Memory reader offset overflow".to_string())
        })?;

        if end > self.data.len() {
            return Err(forensis_core::ForensisError::InvalidFormat(
                "Memory reader range exceeds image".to_string(),
            ));
        }

        buffer.copy_from_slice(&self.data[start..end]);

        Ok(())
    }

    fn size(&self) -> ByteSize {
        ByteSize::new(self.data.len() as u64)
    }
}

fn test_entry(real_size: u64, physical_location: ForensicPhysicalLocation) -> ForensicEntry {
    ForensicEntry::new(
        ForensicIdentity::new(
            "arquivo.txt",
            "/arquivo.txt",
            ForensicEntryKind::File,
            ForensicStatus::Deleted,
            42,
        ),
        ForensicHierarchy::new(Some(5)),
        ForensicMetadata::new(Some(real_size), Some(real_size)),
        ForensicObject::new(ForensicFilesystem::Ntfs, 42),
        ForensicAllocation {
            allocated: Some(false),
            cluster_count: None,
            bitmap_allocated: None,
        },
        physical_location,
    )
}

#[test]
fn test_recover_single_physical_region() {
    /*
     * A sector has 4 bytes in this test.
     *
     * The region starts at sector 2.
     *
     * Therefore:
     *
     * partition_offset = 0
     * sector 2          = byte offset 8
     */
    let image = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'T', b'E', b'S', b'T', 0x00, 0x00, 0x00,
        0x00,
    ];

    let mut reader = MemoryReader::new(image);

    let location = ForensicPhysicalLocation::from_region(ForensicPhysicalRegion::from_ranges(
        2, 2, 2, 2, None,
    ));

    let entry = test_entry(4, location);

    let engine = PhysicalRecoveryEngine::new(0, 4);

    let result = engine.recover(&mut reader, &entry).unwrap();

    assert!(result.is_recovered());

    assert_eq!(result.data(), Some(b"TEST".as_slice()));
}

#[test]
fn test_recover_fragmented_file() {
    /*
     * Each sector has 4 bytes.
     *
     * The content is fragmented:
     *
     * sector 1 -> "ABCD"
     * sector 3 -> "EFGH"
     * sector 5 -> "IJKL"
     */
    let mut image = vec![0u8; 24];

    image[4..8].copy_from_slice(b"ABCD");
    image[12..16].copy_from_slice(b"EFGH");
    image[20..24].copy_from_slice(b"IJKL");

    let mut reader = MemoryReader::new(image);

    let mut location = ForensicPhysicalLocation::empty();

    location.add_region(ForensicPhysicalRegion::from_ranges(1, 1, 1, 1, None));

    location.add_region(ForensicPhysicalRegion::from_ranges(3, 3, 3, 3, None));

    location.add_region(ForensicPhysicalRegion::from_ranges(5, 5, 5, 5, None));

    let entry = test_entry(12, location);

    let engine = PhysicalRecoveryEngine::new(0, 4);

    let result = engine.recover(&mut reader, &entry).unwrap();

    assert!(result.is_recovered());

    assert_eq!(result.data(), Some(b"ABCDEFGHIJKL".as_slice()));
}

#[test]
fn test_recovery_respects_real_size() {
    /*
     * The region has 8 physical bytes,
     * but the file has only 5 real bytes.
     */
    let image = vec![
        0x00, 0x00, 0x00, 0x00, b'H', b'E', b'L', b'L', b'O', b'X', b'X', b'X',
    ];

    let mut reader = MemoryReader::new(image);

    let location = ForensicPhysicalLocation::from_region(ForensicPhysicalRegion::from_ranges(
        1, 2, 1, 2, None,
    ));

    let entry = test_entry(5, location);

    let engine = PhysicalRecoveryEngine::new(0, 4);

    let result = engine.recover(&mut reader, &entry).unwrap();

    assert!(result.is_recovered());

    assert_eq!(result.data(), Some(b"HELLO".as_slice()));
}

#[test]
fn test_recovery_without_physical_region_fails() {
    let image = vec![0u8; 16];

    let mut reader = MemoryReader::new(image);

    let location = ForensicPhysicalLocation::empty();

    let entry = test_entry(4, location);

    let engine = PhysicalRecoveryEngine::new(0, 4);

    let result = engine.recover(&mut reader, &entry).unwrap();

    assert!(!result.is_recovered());

    assert!(result.data().is_none());

    assert_eq!(
        result.reason(),
        Some("Forensic object has no physical recovery regions")
    );
}

#[test]
fn test_recovery_rejects_region_beyond_image() {
    let image = vec![0u8; 8];

    let mut reader = MemoryReader::new(image);

    let location = ForensicPhysicalLocation::from_region(ForensicPhysicalRegion::from_ranges(
        4, 4, 4, 4, None,
    ));

    let entry = test_entry(4, location);

    let engine = PhysicalRecoveryEngine::new(0, 4);

    let result = engine.recover(&mut reader, &entry);

    assert!(result.is_err());
}

#[test]
fn test_recover_sparse_and_fragmented_logical_layout() {
    /*
     * This test represents exactly the geometry
     * of the real case validated on NTFS.
     *
     * Physical geometry:
     *
     *   sector  = 512 bytes
     *   cluster = 4096 bytes
     *   1 cluster = 8 sectors
     *
     * Logical object:
     *
     *   8192 clusters = 32 MiB
     *
     * Layout:
     *
     *   4096 physical clusters
     *   2048 sparse clusters
     *   1943 physical clusters
     *   105  physical clusters
     *
     * Therefore:
     *
     *   4096 + 2048 + 1943 + 105
     *   = 8192 clusters
     *   = 32 MiB
     */

    const BYTES_PER_SECTOR: usize = 512;
    const BYTES_PER_CLUSTER: usize = 4096;
    const SECTORS_PER_CLUSTER: u64 = 8;

    const FIRST_PHYSICAL_CLUSTERS: usize = 4096;
    const SPARSE_CLUSTERS: usize = 2048;
    const SECOND_PHYSICAL_RUN_CLUSTERS: usize = 1943;
    const THIRD_PHYSICAL_RUN_CLUSTERS: usize = 105;

    const FIRST_PHYSICAL_BYTES: usize = FIRST_PHYSICAL_CLUSTERS * BYTES_PER_CLUSTER;

    const SPARSE_BYTES: usize = SPARSE_CLUSTERS * BYTES_PER_CLUSTER;

    const SECOND_PHYSICAL_RUN_BYTES: usize = SECOND_PHYSICAL_RUN_CLUSTERS * BYTES_PER_CLUSTER;

    const THIRD_PHYSICAL_RUN_BYTES: usize = THIRD_PHYSICAL_RUN_CLUSTERS * BYTES_PER_CLUSTER;

    const REAL_SIZE: usize =
        FIRST_PHYSICAL_BYTES + SPARSE_BYTES + SECOND_PHYSICAL_RUN_BYTES + THIRD_PHYSICAL_RUN_BYTES;

    assert_eq!(FIRST_PHYSICAL_BYTES, 16 * 1024 * 1024);

    assert_eq!(SPARSE_BYTES, 8 * 1024 * 1024);

    assert_eq!(
        SECOND_PHYSICAL_RUN_BYTES + THIRD_PHYSICAL_RUN_BYTES,
        8 * 1024 * 1024
    );

    assert_eq!(REAL_SIZE, 32 * 1024 * 1024);

    /*
     * ---------------------------------------------------------
     * REAL GEOMETRY OF OBJECT 83
     * ---------------------------------------------------------
     *
     * First Data Run:
     *
     *   LCN 24680 - 28775
     *   4096 clusters
     *   sectors 197440 - 230207
     */
    const FIRST_LCN_START: u64 = 24680;
    const FIRST_LCN_END: u64 = 28775;

    const FIRST_SECTOR_START: u64 = FIRST_LCN_START * SECTORS_PER_CLUSTER;

    const FIRST_SECTOR_END: u64 = FIRST_LCN_END * SECTORS_PER_CLUSTER + (SECTORS_PER_CLUSTER - 1);

    /*
     * Second Data Run:
     *
     *   LCN 30824 - 32766
     *   1943 clusters
     *   sectors 246592 - 262135
     */
    const SECOND_LCN_START: u64 = 30824;
    const SECOND_LCN_END: u64 = 32766;

    const SECOND_SECTOR_START: u64 = SECOND_LCN_START * SECTORS_PER_CLUSTER;

    const SECOND_SECTOR_END: u64 = SECOND_LCN_END * SECTORS_PER_CLUSTER + (SECTORS_PER_CLUSTER - 1);

    /*
     * Third Data Run:
     *
     *   LCN 57672 - 57776
     *   105 clusters
     *   sectors 461376 - 462215
     */
    const THIRD_LCN_START: u64 = 57672;
    const THIRD_LCN_END: u64 = 57776;

    const THIRD_SECTOR_START: u64 = THIRD_LCN_START * SECTORS_PER_CLUSTER;

    const THIRD_SECTOR_END: u64 = THIRD_LCN_END * SECTORS_PER_CLUSTER + (SECTORS_PER_CLUSTER - 1);

    /*
     * Explicitly protects the
     * cluster -> sector conversion.
     */
    assert_eq!(FIRST_SECTOR_START, 197440);

    assert_eq!(FIRST_SECTOR_END, 230207);

    assert_eq!(SECOND_SECTOR_START, 246592);

    assert_eq!(SECOND_SECTOR_END, 262135);

    assert_eq!(THIRD_SECTOR_START, 461376);

    assert_eq!(THIRD_SECTOR_END, 462215);

    /*
     * ---------------------------------------------------------
     * SYNTHETIC IMAGE
     * ---------------------------------------------------------
     *
     * We do not need to create a 256 MiB image.
     *
     * The LCN/sector numbers above represent the real
     * disk geometry.
     *
     * The `offset` field of the regions lets us place the
     * physical data in a small image while keeping the real
     * physical numbers in the metadata.
     */

    let physical_a_offset: usize = 0;

    let physical_b_offset = FIRST_PHYSICAL_BYTES + 4 * BYTES_PER_CLUSTER;

    let physical_c_offset = physical_b_offset + SECOND_PHYSICAL_RUN_BYTES + 4 * BYTES_PER_CLUSTER;

    let image_size = physical_c_offset + THIRD_PHYSICAL_RUN_BYTES;

    let mut image = vec![0u8; image_size];

    /*
     * Region A:
     * 16 MiB physical.
     */
    for index in 0..FIRST_PHYSICAL_BYTES {
        image[physical_a_offset + index] = (index % 251) as u8;
    }

    /*
     * Region B:
     * first physical fragment of the final stretch.
     */
    for index in 0..SECOND_PHYSICAL_RUN_BYTES {
        image[physical_b_offset + index] = ((index + 17) % 251) as u8;
    }

    /*
     * Region C:
     * second physical fragment of the final stretch.
     */
    for index in 0..THIRD_PHYSICAL_RUN_BYTES {
        image[physical_c_offset + index] = ((index + 113) % 251) as u8;
    }

    let mut reader = MemoryReader::new(image);

    /*
     * ---------------------------------------------------------
     * PHYSICAL REGIONS
     * ---------------------------------------------------------
     *
     * The cluster_start/end and sector_start/end fields
     * represent the real geometry.
     *
     * The offset field points to the corresponding position
     * inside the small synthetic image.
     */

    let first_region = ForensicPhysicalRegion::from_ranges(
        FIRST_LCN_START,
        FIRST_LCN_END,
        FIRST_SECTOR_START,
        FIRST_SECTOR_END,
        Some(physical_a_offset as u64),
    );

    let second_region = ForensicPhysicalRegion::from_ranges(
        SECOND_LCN_START,
        SECOND_LCN_END,
        SECOND_SECTOR_START,
        SECOND_SECTOR_END,
        Some(physical_b_offset as u64),
    );

    let third_region = ForensicPhysicalRegion::from_ranges(
        THIRD_LCN_START,
        THIRD_LCN_END,
        THIRD_SECTOR_START,
        THIRD_SECTOR_END,
        Some(physical_c_offset as u64),
    );

    /*
     * The logical layout is:
     *
     *   [0, 4096)       -> physical A
     *   [4096, 6144)    -> sparse
     *   [6144, 8087)    -> physical B
     *   [8087, 8192)    -> physical C
     */

    let layout = ForensicContentLayout::new(
        BYTES_PER_CLUSTER as u64,
        vec![
            ForensicContentSegment::physical(0, FIRST_PHYSICAL_CLUSTERS as u64, first_region),
            ForensicContentSegment::sparse(FIRST_PHYSICAL_CLUSTERS as u64, SPARSE_CLUSTERS as u64),
            ForensicContentSegment::physical(
                (FIRST_PHYSICAL_CLUSTERS + SPARSE_CLUSTERS) as u64,
                SECOND_PHYSICAL_RUN_CLUSTERS as u64,
                second_region,
            ),
            ForensicContentSegment::physical(
                (FIRST_PHYSICAL_CLUSTERS + SPARSE_CLUSTERS + SECOND_PHYSICAL_RUN_CLUSTERS) as u64,
                THIRD_PHYSICAL_RUN_CLUSTERS as u64,
                third_region,
            ),
        ],
    );

    let mut entry = test_entry(REAL_SIZE as u64, ForensicPhysicalLocation::empty());

    entry.content_layout = layout;

    /*
     * The engine works with real physical sectors:
     *
     *   512 bytes per sector
     */
    let engine = PhysicalRecoveryEngine::new(0, BYTES_PER_SECTOR as u64);

    let result = engine.recover(&mut reader, &entry).unwrap();

    assert!(result.is_recovered());

    let data = result.data().expect("Recovered object must contain data");

    /*
     * The result must have exactly
     * the logical size of the file.
     */
    assert_eq!(data.len(), REAL_SIZE);

    /*
     * ---------------------------------------------------------
     * FIRST RUN VALIDATION
     * ---------------------------------------------------------
     */
    assert_eq!(
        &data[0..FIRST_PHYSICAL_BYTES],
        &reader.data[physical_a_offset..physical_a_offset + FIRST_PHYSICAL_BYTES],
    );

    /*
     * ---------------------------------------------------------
     * SPARSE VALIDATION
     * ---------------------------------------------------------
     *
     * The logical range from 16 MiB to 24 MiB
     * must be completely filled with zero.
     */
    assert!(
        data[FIRST_PHYSICAL_BYTES..FIRST_PHYSICAL_BYTES + SPARSE_BYTES]
            .iter()
            .all(|byte| *byte == 0)
    );

    /*
     * ---------------------------------------------------------
     * SECOND RUN VALIDATION
     * ---------------------------------------------------------
     */
    let logical_second_start = FIRST_PHYSICAL_BYTES + SPARSE_BYTES;

    assert_eq!(
        &data[logical_second_start..logical_second_start + SECOND_PHYSICAL_RUN_BYTES],
        &reader.data[physical_b_offset..physical_b_offset + SECOND_PHYSICAL_RUN_BYTES],
    );

    /*
     * ---------------------------------------------------------
     * THIRD RUN VALIDATION
     * ---------------------------------------------------------
     */
    let logical_third_start = logical_second_start + SECOND_PHYSICAL_RUN_BYTES;

    assert_eq!(
        &data[logical_third_start..logical_third_start + THIRD_PHYSICAL_RUN_BYTES],
        &reader.data[physical_c_offset..physical_c_offset + THIRD_PHYSICAL_RUN_BYTES],
    );

    /*
     * The final sum must represent exactly
     * the 8192 logical clusters of the file.
     */
    assert_eq!(
        data.len(),
        FIRST_PHYSICAL_BYTES + SPARSE_BYTES + SECOND_PHYSICAL_RUN_BYTES + THIRD_PHYSICAL_RUN_BYTES,
    );

    assert_eq!(data.len(), 8192 * BYTES_PER_CLUSTER);
}

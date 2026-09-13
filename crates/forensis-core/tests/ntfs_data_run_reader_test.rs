use std::path::Path;

use forensis_core::filesystem::ntfs::{DataRun, DataRunReader};

use forensis_core::image_reader::ImageReader;

fn test_image_path() -> String {
    format!("{}/../../lab/ntfs/disk.img", env!("CARGO_MANIFEST_DIR"))
}

fn image_available() -> bool {
    Path::new(&test_image_path()).exists()
}

#[test]
fn test_lcn_offset() {
    let reader = DataRunReader::new(2048, 4096);

    assert_eq!(reader.lcn_offset(0), 2048,);

    assert_eq!(reader.lcn_offset(10), 43008,);
}

#[test]
fn test_read_run() {
    let image_path = test_image_path();

    if !image_available() {
        eprintln!("skipping: lab/ntfs/disk.img not available");
        return;
    }

    let image = ImageReader::open(&image_path).unwrap();

    let mut image = image;

    let reader = DataRunReader::new(0, 4096);

    let run = DataRun {
        lcn: Some(0),
        cluster_count: 1,
    };

    let data = reader.read_run(&mut image, &run).unwrap();

    assert_eq!(data.len(), 4096,);
}

#[test]
fn test_read_multiple_runs() {
    let image_path = test_image_path();

    if !image_available() {
        eprintln!("skipping: lab/ntfs/disk.img not available");
        return;
    }

    let image = ImageReader::open(&image_path).unwrap();

    let mut image = image;

    let reader = DataRunReader::new(0, 4096);

    let runs = [
        DataRun {
            lcn: Some(0),
            cluster_count: 2,
        },
        DataRun {
            lcn: Some(2),
            cluster_count: 2,
        },
    ];

    /*
     * 4 clusters × 4096 bytes
     * = 16384 bytes.
     */
    let real_size = 16384u64;

    let data = reader.read_runs(&mut image, &runs, real_size).unwrap();

    assert_eq!(data.len(), real_size as usize,);
}

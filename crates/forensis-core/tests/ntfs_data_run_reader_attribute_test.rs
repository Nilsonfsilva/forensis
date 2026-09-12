use forensis_core::filesystem::ntfs::{DataAttribute, DataRun, DataRunReader};

use forensis_core::image_reader::ImageReader;

fn test_image_path() -> String {
    format!("{}/../../lab/ntfs/disk.img", env!("CARGO_MANIFEST_DIR"),)
}

#[test]
fn test_read_resident_attribute() {
    let attribute = DataAttribute {
        non_resident: false,
        real_size: 5,
        allocated_size: 5,
        resident_data: Some(b"hello".to_vec()),
        data_runs: Vec::new(),
    };

    let reader = DataRunReader::new(0, 4096);

    let image_path = test_image_path();

    let mut image = ImageReader::open(&image_path).unwrap();

    let data = reader.read_attribute(&mut image, &attribute).unwrap();

    assert_eq!(data, b"hello",);
}

#[test]
fn test_read_non_resident_attribute() {
    let attribute = DataAttribute {
        non_resident: true,
        real_size: 4096,
        allocated_size: 4096,
        resident_data: None,
        data_runs: vec![DataRun {
            lcn: Some(0),
            cluster_count: 1,
        }],
    };

    let reader = DataRunReader::new(0, 4096);

    let image_path = test_image_path();

    let mut image = ImageReader::open(&image_path).unwrap();

    let data = reader.read_attribute(&mut image, &attribute).unwrap();

    assert_eq!(data.len(), 4096,);
}

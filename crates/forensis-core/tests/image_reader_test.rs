use std::fs::File;
use std::io::Write;

use forensis_core::{ByteOffset, ImageReader, Readable};

#[test]
fn test_image_reader_reads_bytes() {
    let path = "test_image.dd";

    let mut file = File::create(path).unwrap();

    file.write_all(&[0x46, 0x4F, 0x52, 0x45, 0x4E, 0x53, 0x49, 0x53])
        .unwrap();

    drop(file);

    let mut reader = ImageReader::open(path).unwrap();

    let mut buffer = [0u8; 8];

    reader.read_at(ByteOffset::new(0), &mut buffer).unwrap();

    assert_eq!(&buffer, b"FORENSIS");

    std::fs::remove_file(path).unwrap();
}

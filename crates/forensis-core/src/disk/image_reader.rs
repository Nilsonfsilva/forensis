use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[cfg(target_os = "linux")]
use crate::error::ForensisError;
use crate::result::Result;
use crate::traits::Readable;
use crate::types::{ByteOffset, ByteSize};

pub struct ImageReader {
    file: File,
    size: ByteSize,
}

impl ImageReader {
    pub fn open(path: &str) -> Result<Self> {
        let path = Path::new(path);

        let mut file = File::open(path)?;

        let size = if is_block_device(path)? {
            block_device_size(path)?
        } else {
            file.seek(SeekFrom::End(0))?
        };

        file.seek(SeekFrom::Start(0))?;

        Ok(Self {
            file,
            size: ByteSize::new(size),
        })
    }
}

fn is_block_device(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        Ok(metadata.file_type().is_block_device())
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn block_device_size(path: &Path) -> Result<u64> {
    let canonical_path = fs::canonicalize(path)?;

    let device_name = canonical_path
        .file_name()
        .ok_or_else(|| ForensisError::Generic("Unable to determine the device name.".to_string()))?
        .to_string_lossy();

    let sysfs_path = Path::new("/sys/class/block")
        .join(device_name.as_ref())
        .join("size");

    let sectors = fs::read_to_string(&sysfs_path)?
        .trim()
        .parse::<u64>()
        .map_err(|error| {
            ForensisError::Generic(format!(
                "Invalid size in {}: {}",
                sysfs_path.display(),
                error
            ))
        })?;

    sectors.checked_mul(512).ok_or_else(|| {
        ForensisError::Generic("Overflow while computing the device size.".to_string())
    })
}

#[cfg(not(target_os = "linux"))]
fn block_device_size(path: &Path) -> Result<u64> {
    let mut file = File::open(path)?;

    Ok(file.seek(SeekFrom::End(0))?)
}

impl Readable for ImageReader {
    fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset.value()))?;

        self.file.read_exact(buffer)?;

        Ok(())
    }

    fn size(&self) -> ByteSize {
        self.size
    }
}

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result};
use forensis_core::EvidenceSource;

/// Discovers the available sources from a path.
///
/// This function belongs to the application layer.
///
/// It does NOT show menus and does NOT interact with the user.
/// It only transforms the given path into evidence sources
/// that can later be presented by the CLI or the TUI.
///
/// Rules:
///
/// - regular file -> one `DiskImage` source;
/// - block device -> `BlockDevice` or `Partition`;
/// - directory -> discovers the sources existing in the directory.
///
/// Source selection belongs exclusively to the interface.
pub fn discover_sources(path: impl AsRef<Path>) -> Result<Vec<EvidenceSource>> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(anyhow!("Evidence source not found: {}", path.display()));
    }

    let metadata = fs::metadata(path)?;

    if metadata.is_file() {
        return Ok(vec![EvidenceSource::disk_image(path.to_path_buf())]);
    }

    if is_block_device(path)? {
        if is_partition_device(path)? {
            return Ok(vec![EvidenceSource::partition(path.to_path_buf())]);
        }

        return Ok(vec![EvidenceSource::block_device(path.to_path_buf())]);
    }

    if metadata.is_dir() {
        return discover_directory_sources(path);
    }

    Err(anyhow!("Unsupported evidence source: {}", path.display()))
}

/// Discovers sources inside a directory.
///
/// For `/dev/`, block devices are classified
/// as `BlockDevice` or `Partition`.
///
/// For other directories, regular files are
/// considered possible forensic images.
///
/// No user interaction happens here.
fn discover_directory_sources(directory: &Path) -> Result<Vec<EvidenceSource>> {
    let is_dev_directory = directory == Path::new("/dev");

    let mut sources = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if is_dev_directory {
            if is_block_device(&path)? {
                if is_partition_device(&path)? {
                    sources.push(EvidenceSource::partition(path));
                } else {
                    sources.push(EvidenceSource::block_device(path));
                }
            }
        } else if metadata.is_file() {
            sources.push(EvidenceSource::disk_image(path));
        }
    }

    sources.sort_by(|a, b| {
        a.path()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .cmp(&b.path().file_name().unwrap_or_default().to_string_lossy())
    });

    if sources.is_empty() {
        if is_dev_directory {
            return Err(anyhow!(
                "No block devices found in {}",
                directory.display()
            ));
        }

return Err(anyhow!(
                "No files found in {}",
                directory.display()
            ));
    }

    Ok(sources)
}

/// Checks whether the path represents a block device.
///
/// This function encapsulates the operating system
/// specifics.
///
/// The rest of the application does not need to know how
/// the operating system identifies a block device.
fn is_block_device(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        return Ok(metadata.file_type().is_block_device());
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;

        Ok(false)
    }
}

/// Checks whether a block device represents a partition.
///
/// The identification is operating-system specific and stays
/// encapsulated in this application layer.
///
/// On Linux, the kernel exposes this information through
/// `/sys/class/block/<device>/partition`.
fn is_partition_device(path: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let name = match path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => return Ok(false),
        };

        let partition_path = Path::new("/sys/class/block")
            .join(name.as_ref())
            .join("partition");

        return Ok(partition_path.exists());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;

        Ok(false)
    }
}

/// Resolves a directly provided source.
///
/// Unlike `discover_sources()`, this function
/// expects the path to already identify a single source.
///
/// It does not show menus and does not read user input.
///
/// For directories, use `discover_sources()` and leave
/// the interface responsible for the selection.
pub fn resolve_source(path: impl AsRef<Path>) -> Result<EvidenceSource> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(anyhow!("Evidence source not found: {}", path.display()));
    }

    let metadata = fs::metadata(path)?;

    if metadata.is_file() {
        return Ok(EvidenceSource::disk_image(path.to_path_buf()));
    }

    if is_block_device(path)? {
        if is_partition_device(path)? {
            return Ok(EvidenceSource::partition(path.to_path_buf()));
        }

        return Ok(EvidenceSource::block_device(path.to_path_buf()));
    }

    if metadata.is_dir() {
        return Err(anyhow!(
            "{} is a directory. \
             Use discover_sources() to discover \
             the available sources.",
            path.display()
        ));
    }

    Err(anyhow!("Unsupported evidence source: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensis_core::EvidenceSourceKind;

    #[test]
    fn regular_file_is_resolved_as_disk_image() {
        let directory = tempfile::tempdir().unwrap();

        let image = directory.path().join("disk.img");

        fs::write(&image, b"forensis").unwrap();

        let source = resolve_source(&image).unwrap();

        assert_eq!(source.path(), image.as_path());

        assert_eq!(source.kind(), EvidenceSourceKind::DiskImage);

        assert!(source.is_disk_image());
        assert!(!source.is_partition());
        assert!(!source.is_block_device());
    }

    #[test]
    fn regular_file_is_discovered() {
        let directory = tempfile::tempdir().unwrap();

        let image = directory.path().join("disk.img");

        fs::write(&image, b"forensis").unwrap();

        let sources = discover_sources(&image).unwrap();

        assert_eq!(sources.len(), 1);

        assert_eq!(sources[0].path(), image.as_path());

        assert_eq!(sources[0].kind(), EvidenceSourceKind::DiskImage);
    }

    #[test]
    fn directory_sources_are_discovered() {
        let directory = tempfile::tempdir().unwrap();

        let image_a = directory.path().join("b.img");

        let image_b = directory.path().join("a.img");

        fs::write(&image_a, b"forensis").unwrap();

        fs::write(&image_b, b"forensis").unwrap();

        let sources = discover_sources(directory.path()).unwrap();

        assert_eq!(sources.len(), 2);

        assert_eq!(sources[0].path(), image_b.as_path());

        assert_eq!(sources[1].path(), image_a.as_path());

        assert!(sources[0].is_disk_image());

        assert!(sources[1].is_disk_image());
    }

    #[test]
    fn directory_cannot_be_resolved_directly() {
        let directory = tempfile::tempdir().unwrap();

        let result = resolve_source(directory.path());

        assert!(result.is_err());
    }

    #[test]
    fn missing_source_fails() {
        let directory = tempfile::tempdir().unwrap();

        let missing = directory.path().join("missing.img");

        let result = resolve_source(&missing);

        assert!(result.is_err());
    }
}

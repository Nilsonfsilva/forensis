use crate::result::Result;

/// Interface for reading storage devices.
///
/// A DiskReader can represent:
///
/// - a physical disk;
/// - a .dd image;
/// - a .img image;
/// - a test file;
/// - a virtual disk.
pub trait DiskReader {
    /// Reads bytes from an absolute offset.
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()>;

    /// Returns the device size in bytes.
    fn size(&self) -> u64;

    /// Closes the device.
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

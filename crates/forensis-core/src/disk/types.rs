use crate::platform::Platform;

/// Storage device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskKind {
    /// Physical disk (HD, SSD, NVMe, pendrive, etc.)
    Physical,

    /// Forensic image file (.img, .dd, ...)
    Image,

    /// Virtual disk (VHD, VMDK, QCOW2...)
    Virtual,

    /// Network device (future implementation)
    Network,

    /// Unknown type
    Unknown,
}

/// Represents a storage device.
#[derive(Debug, Clone)]
pub struct Disk {
    /// Internal identifier.
    pub id: u32,

    /// Friendly device name.
    pub name: String,

    /// Path used to open the device.
    pub path: String,

    /// Total size in bytes.
    pub size: u64,

    /// Physical sector size.
    pub sector_size: u32,

    /// Operating system where the device was detected.
    pub platform: Platform,

    /// Device type.
    pub kind: DiskKind,
}

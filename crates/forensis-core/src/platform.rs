/// Operating systems supported by Forensis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    AArch64,
    Unknown,
}

impl Platform {
    /// Returns the current operating system.
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOS
        } else {
            Self::Unknown
        }
    }
}

impl Architecture {
    /// Returns the current processor architecture.
    pub fn current() -> Self {
        if cfg!(target_arch = "x86") {
            Self::X86
        } else if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else if cfg!(target_arch = "arm") {
            Self::Arm
        } else if cfg!(target_arch = "aarch64") {
            Self::AArch64
        } else {
            Self::Unknown
        }
    }
}

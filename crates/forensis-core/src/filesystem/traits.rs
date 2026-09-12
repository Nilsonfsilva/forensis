// Common filesystem interface for forensic analysis.
//
// Every filesystem implementation must provide
// a standard way to expose its information.

use crate::filesystem::FileSystemType;

pub trait FileSystem {
    // Returns the detected filesystem type.
    fn filesystem_type(&self) -> FileSystemType;

    // Lists files and directories available
    // through the filesystem metadata.
    fn list_files(&self) -> Vec<String>;

    // Returns general filesystem metadata.
    fn metadata(&self) -> String;
}

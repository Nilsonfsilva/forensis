use std::collections::{HashMap, HashSet, VecDeque};

use super::extent_tree::resolve_extents;
use super::{Ext4Extent, Ext4Filesystem, Ext4Inode, Ext4InodeBitmap, Ext4Reader};

use crate::forensic::{ForensicEntry, ForensicFilesystem, ForensicModel, ForensicSource};
use crate::progress::{NoProgress, ProgressEvent, ProgressPhase, ProgressReporter, ProgressUnit};
use crate::result::Result;
use crate::traits::Readable;

use super::Ext4InvestigationEntry;

/// EXT4 root directory inode number.
pub const ROOT_INODE: u32 = 2;

/// EXT4 sector size used by the forensic image.
const EXT4_BYTES_PER_SECTOR: u64 = 512;

/// Maximum filename length supported by EXT4.
const EXT4_MAX_NAME_LENGTH: usize = 255;

/// Internal result of the EXT4 investigation.
///
/// This structure belongs exclusively to the EXT4 layer.
///
/// It may know about:
///
/// - inodes
/// - extent trees
/// - directory entries
/// - block groups
/// - inode bitmaps
///
/// The application must not consume this structure directly.
///
/// The public filesystem output is converted into
/// `ForensicModel`.
#[derive(Debug)]
pub struct Ext4Investigation {
    entries: Vec<Ext4InvestigationEntry>,

    /// Number of inodes actually processed during the
    /// investigation.
    records: u64,

    /// Number of bytes contained in one filesystem block.
    bytes_per_block: u64,

    /// Number of 512-byte sectors contained in one
    /// filesystem block.
    sectors_per_block: u64,
}

impl Ext4Investigation {
    /// Creates an empty EXT4 investigation.
    pub fn new(bytes_per_block: u64, bytes_per_sector: u64) -> Self {
        Self {
            entries: Vec::new(),
            records: 0,
            bytes_per_block,
            sectors_per_block: bytes_per_block / bytes_per_sector,
        }
    }

    /// Adds an entry to the EXT4 investigation.
    pub fn add_entry(&mut self, entry: Ext4InvestigationEntry) {
        self.entries.push(entry);
    }

    /// Increments the number of processed inodes.
    pub fn increment_records(&mut self) {
        self.records += 1;
    }

    /// Returns the number of discovered entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of processed inodes.
    pub fn record_count(&self) -> u64 {
        self.records
    }

    /// Returns the filesystem block size.
    pub fn bytes_per_block(&self) -> u64 {
        self.bytes_per_block
    }

    /// Returns all EXT4 investigation entries.
    pub fn entries(&self) -> &[Ext4InvestigationEntry] {
        &self.entries
    }

    /// Resolves the absolute path of an EXT4 entry.
    ///
    /// The path is built by walking the entry, its parent
    /// directory, its grandparent and so on up to the root.
    ///
    /// The resolution happens exclusively inside the EXT4
    /// layer because only this layer knows the semantics of
    /// `parent_inode`.
    fn resolve_path(&self, entry: &Ext4InvestigationEntry) -> String {
        /*
         * The root directory is recognized by having its
         * parent pointing to itself.
         */
        if entry.is_directory() && entry.inode_number() == entry.parent_inode() {
            return "/".to_string();
        }

        let mut components = Vec::new();

        let mut current_inode = entry.inode_number();

        let mut visited = Vec::new();

        loop {
            /*
             * Protection against corruption or a cycle in the
             * hierarchy. Forensic evidence must not allow a
             * corrupted structure to cause an infinite loop.
             */
            if visited.contains(&current_inode) {
                break;
            }

            visited.push(current_inode);

            let current = match self
                .entries
                .iter()
                .find(|candidate| candidate.inode_number() == current_inode)
            {
                Some(value) => value,

                None => break,
            };

            /*
             * The root must not appear as a component of the path.
             *
             * An entry whose parent points to itself is treated as
             * the root, exactly as NTFS roots are recognized.
             */
            if current.inode_number() == current.parent_inode() {
                break;
            }

            if current.inode_number() == ROOT_INODE {
                break;
            }

            components.push(current.name().to_string());

            current_inode = current.parent_inode();
        }

        components.reverse();

        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    /// Converts the internal EXT4 result into the
    /// filesystem-independent forensic model.
    ///
    /// After this conversion, the application no longer needs
    /// to know about `Ext4InvestigationEntry`, inodes, extents
    /// or other EXT4-specific structures.
    pub fn to_forensic_model(&self, image: Option<String>) -> ForensicModel {
        let entries: Vec<ForensicEntry> = self
            .entries
            .iter()
            .map(|entry| {
                let mut forensic_entry =
                    entry.to_forensic_entry(self.bytes_per_block, self.sectors_per_block);

                /*
                 * The path is resolved while we are still inside
                 * the EXT4 layer.
                 */
                forensic_entry.identity.path = self.resolve_path(entry);

                forensic_entry
            })
            .collect();

        ForensicModel::new(
            ForensicSource::new(image, ForensicFilesystem::Ext4),
            self.records,
            entries,
        )
    }
}

/// Investigates an EXT4 filesystem.
///
/// The walk starts at the root directory (inode 2) and
/// recursively descends into the directory hierarchy.
///
/// Deleted files are recovered through two complementary scans:
///
/// - residual directory entries whose inode is still allocated
///   and carries a non-zero deletion timestamp;
/// - inode table positions that are allocated in the inode
///   bitmap but whose inode is deleted (deletion timestamp set,
///   link count cleared).
pub fn investigate_filesystem<R: Readable>(
    filesystem: &Ext4Filesystem,
    reader: &mut Ext4Reader<R>,
) -> Result<Ext4Investigation> {
    investigate_filesystem_with_progress(filesystem, reader, &NoProgress)
}

/// Investigates an EXT4 filesystem and reports progress.
///
/// The walk has two moments that both report progress:
///
/// - the reachable-directory walk, reported as an indeterminate
///   counter of processed inodes;
/// - the inode table scan for deleted files, reported as a determined
///   percentage because the total number of inode slots is known.
pub fn investigate_filesystem_with_progress<R: Readable>(
    filesystem: &Ext4Filesystem,
    reader: &mut Ext4Reader<R>,
    reporter: &dyn ProgressReporter,
) -> Result<Ext4Investigation> {
    let superblock = filesystem.superblock();

    let bytes_per_block = superblock.block_size() as u64;

    let bytes_per_sector = EXT4_BYTES_PER_SECTOR;

    let inodes_per_group = superblock.inodes_per_group();

    let mut investigation = Ext4Investigation::new(bytes_per_block, bytes_per_sector);

    let mut visited: HashSet<u32> = HashSet::new();

    let mut bitmap_cache: HashMap<u32, Ext4InodeBitmap> = HashMap::new();

    /*
     * Residual directory entries discovered during the walk.
     * They provide the recovered name and parent directory of
     * deleted files found later in the inode table scan.
     */
    let mut residual_names: HashMap<u32, (String, u32)> = HashMap::new();

    let mut queue: VecDeque<(u32, u32, String)> = VecDeque::new();

    queue.push_back((ROOT_INODE, ROOT_INODE, String::new()));

    while let Some((inode_number, parent_inode, name)) = queue.pop_front() {
        if inode_number == 0 || !visited.insert(inode_number) {
            continue;
        }

        let inode = match filesystem.read_inode(reader, inode_number) {
            Ok(inode) => inode,

            Err(_) => continue,
        };

        investigation.increment_records();

        reporter.report(ProgressEvent::indeterminate(
            ProgressPhase::ProcessingRecords,
            investigation.record_count(),
            ProgressUnit::Inodes,
        ));

        let group = (inode_number - 1) / inodes_per_group;

        let bitmap = match bitmap_cache.entry(group) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let value = match filesystem.read_inode_bitmap(reader, group as usize) {
                    Ok(bitmap) => bitmap,

                    Err(_) => Ext4InodeBitmap::parse(&[0u8; 1])?,
                };

                entry.insert(value)
            }
        };

        let bitmap_allocated = bitmap.is_allocated(inode_number as u64);

        let extents: Vec<Ext4Extent> =
            resolve_extents(reader, superblock, &inode).unwrap_or_default();

        let data = if inode.is_symlink() {
            inode.fast_symlink_target()
        } else {
            None
        };

        if inode.is_directory() && inode.dtime() == 0 {
            let entries = read_directory_entries(filesystem, reader, &inode, &extents);

            if let Ok(entries) = entries {
                for entry in entries {
                    if entry.is_unused() {
                        continue;
                    }

                    if entry.name() == "." || entry.name() == ".." || entry.name().is_empty() {
                        continue;
                    }

                    queue.push_back((entry.inode(), inode_number, entry.name().to_string()));
                }
            }

            /*
             * Residual scan for deleted file name remnants.
             */
            let residual = scan_directory_for_deleted(filesystem, reader, &extents);

            for (residual_inode, residual_name) in residual {
                if !visited.contains(&residual_inode) {
                    residual_names
                        .entry(residual_inode)
                        .or_insert((residual_name, inode_number));
                }
            }
        }

        investigation.add_entry(build_entry(
            &inode,
            inode_number,
            parent_inode,
            name,
            extents,
            data,
            bitmap_allocated,
        ));
    }

    /*
     * ---------------------------------------------------------
     * INODE TABLE SCAN FOR DELETED FILES
     * ---------------------------------------------------------
     *
     * Deleted files keep their allocated inode position until
     * the inode is reused. The inode itself carries the deletion
     * timestamp. This scan finds files removed from their
     * directory entries whose inode has not yet been reused.
     */
    let group_count = filesystem.block_group_count();

    let total_inodes = (group_count as u64).saturating_mul(u64::from(inodes_per_group));

    for group in 0..group_count {
        let processed_inodes = (group as u64 + 1) * u64::from(inodes_per_group);

        /*
         * Report once per group. The total number of inode slots
         * is known in advance, so the scan is a determinate counter.
         */
        reporter.report(ProgressEvent::new(
            ProgressPhase::ProcessingRecords,
            processed_inodes.min(total_inodes),
            total_inodes.max(1),
            ProgressUnit::Inodes,
        ));

        let (_, bitmap, table) = match filesystem.read_block_group(reader, group) {
            Ok(metadata) => metadata,

            Err(_) => continue,
        };

        for slot in 0..table.inode_count() {
            let inode_number =
                match u32::try_from(group as u64 * inodes_per_group as u64 + slot + 1) {
                    Ok(value) => value,

                    Err(_) => continue,
                };

            if inode_number == 0 || visited.contains(&inode_number) {
                continue;
            }

            if !bitmap.is_allocated(inode_number as u64) {
                continue;
            }

            let raw = match table.inode(slot) {
                Ok(raw) => raw,

                Err(_) => continue,
            };

            let inode = match Ext4Inode::parse(raw) {
                Ok(inode) => inode,

                Err(_) => continue,
            };

            if inode.dtime() == 0 || inode.links_count() != 0 {
                continue;
            }

            investigation.increment_records();

            let (name, parent_inode) = residual_names
                .get(&inode_number)
                .cloned()
                .unwrap_or_else(|| (format!("inode-{}", inode_number), ROOT_INODE));

            let extents: Vec<Ext4Extent> =
                resolve_extents(reader, superblock, &inode).unwrap_or_default();

            let data = if inode.is_symlink() {
                inode.fast_symlink_target()
            } else {
                None
            };

            investigation.add_entry(build_entry(
                &inode,
                inode_number,
                parent_inode,
                name,
                extents,
                data,
                true,
            ));

            visited.insert(inode_number);
        }
    }

    reporter.report(ProgressEvent::completed());

    Ok(investigation)
}

/// Builds an EXT4 investigation entry from an inode.
fn build_entry(
    inode: &Ext4Inode,
    inode_number: u32,
    parent_inode: u32,
    name: String,
    extents: Vec<Ext4Extent>,
    data: Option<Vec<u8>>,
    bitmap_allocated: bool,
) -> Ext4InvestigationEntry {
    Ext4InvestigationEntry::new(
        inode_number,
        parent_inode,
        name,
        inode.is_directory(),
        inode.size(),
        inode.blocks() * EXT4_BYTES_PER_SECTOR,
        inode.mode(),
        inode.flags(),
        inode.dtime(),
        inode.links_count(),
        extents,
        data,
        bitmap_allocated,
    )
}

/// Reads the directory entries contained in the data blocks
/// of a directory inode.
fn read_directory_entries<R: Readable>(
    filesystem: &Ext4Filesystem,
    reader: &mut Ext4Reader<R>,
    inode: &Ext4Inode,
    extents: &[Ext4Extent],
) -> Result<Vec<crate::filesystem::ext4::Ext4DirectoryEntry>> {
    use crate::filesystem::ext4::Ext4DirectoryEntry;

    let superblock = filesystem.superblock();

    let block_size = superblock.block_size() as u64;

    let mut entries = Vec::new();

    for extent in extents {
        if extent.length() == 0 || !extent.is_initialized() {
            continue;
        }

        let mut logical_block = extent.logical_block() as u64;

        for delta in 0..extent.length() as u64 {
            let directory_offset = logical_block.saturating_mul(block_size);

            if directory_offset >= inode.size() {
                break;
            }

            let physical_block = extent.physical_block() + delta;

            let data = match reader.read_block(superblock, physical_block) {
                Ok(data) => data,

                Err(_) => {
                    logical_block += 1;
                    continue;
                }
            };

            if let Ok(block_entries) = Ext4DirectoryEntry::parse_block(&data) {
                entries.extend(block_entries);
            }

            logical_block += 1;
        }
    }

    Ok(entries)
}

/// Scans directory data blocks for residual deleted entries.
///
/// When a file is removed, EXT4 zeroes the inode number of its
/// directory entry, but remnants of previously valid entries may
/// remain in the unused area of the directory block.
///
/// The scan looks for 8-byte headers with a valid structure and
/// returns the surviving inode/name pairs. Their interpretation
/// is confirmed later against the inode table.
fn scan_directory_for_deleted<R: Readable>(
    filesystem: &Ext4Filesystem,
    reader: &mut Ext4Reader<R>,
    extents: &[Ext4Extent],
) -> Vec<(u32, String)> {
    let superblock = filesystem.superblock();

    let block_size = superblock.block_size() as usize;

    let mut found = Vec::new();

    for extent in extents {
        if extent.length() == 0 || !extent.is_initialized() {
            continue;
        }

        for delta in 0..extent.length() as u64 {
            let physical_block = extent.physical_block() + delta;

            let data = match reader.read_block(superblock, physical_block) {
                Ok(data) => data,

                Err(_) => continue,
            };

            scan_block_for_deleted_headers(&data, block_size, &mut found);
        }
    }

    found
}

/// Scans one directory data block for residual entry headers.
fn scan_block_for_deleted_headers(data: &[u8], block_size: usize, found: &mut Vec<(u32, String)>) {
    for offset in 0..data.len() {
        let remaining = &data[offset..];

        if remaining.len() < 8 {
            break;
        }

        let inode = u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);

        let record_length = u16::from_le_bytes([remaining[4], remaining[5]]) as usize;

        let name_length = remaining[6] as usize;

        let file_type = remaining[7];

        if inode == 0 {
            continue;
        }

        if record_length < 8 || offset + record_length > block_size {
            continue;
        }

        if name_length == 0 || name_length > EXT4_MAX_NAME_LENGTH {
            continue;
        }

        if 8 + name_length > record_length {
            continue;
        }

        if file_type > 7 {
            continue;
        }

        let name = String::from_utf8_lossy(&remaining[8..8 + name_length]).to_string();

        if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
            continue;
        }

        found.push((inode, name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::{ForensicEntryKind, ForensicFilesystem};

    fn entry(
        inode_number: u32,
        parent_inode: u32,
        name: &str,
        is_directory: bool,
    ) -> Ext4InvestigationEntry {
        Ext4InvestigationEntry::new(
            inode_number,
            parent_inode,
            name.to_string(),
            is_directory,
            0,
            0,
            if is_directory { 0x41ED } else { 0x81A4 },
            0,
            0,
            1,
            vec![],
            None,
            true,
        )
    }

    fn nested_investigation() -> Ext4Investigation {
        let mut investigation = Ext4Investigation::new(4096, 512);

        investigation.add_entry(entry(2, 2, "", true));
        investigation.add_entry(entry(3, 2, "nivel1", true));
        investigation.add_entry(entry(4, 3, "arquivo.txt", false));

        investigation
    }

    #[test]
    fn root_resolves_to_root_path() {
        let investigation = nested_investigation();

        let root = investigation
            .entries()
            .iter()
            .find(|e| e.inode_number() == 2)
            .unwrap();

        assert_eq!(investigation.resolve_path(root), "/");
    }

    #[test]
    fn nested_entry_resolves_full_path() {
        let investigation = nested_investigation();

        let arquivo = investigation
            .entries()
            .iter()
            .find(|e| e.inode_number() == 4)
            .unwrap();

        assert_eq!(investigation.resolve_path(arquivo), "/nivel1/arquivo.txt");
    }

    #[test]
    fn cycle_produces_safe_path() {
        let mut investigation = nested_investigation();

        /*
         * A malicious or corrupted entry whose parent points to
         * itself must not loop forever.
         */
        investigation.add_entry(entry(10, 10, "corrompido", false));

        let corrupted = investigation
            .entries()
            .iter()
            .find(|e| e.inode_number() == 10)
            .unwrap();

        assert_eq!(investigation.resolve_path(corrupted), "/");
    }

    #[test]
    fn missing_parent_keeps_partial_path() {
        let mut investigation = nested_investigation();

        investigation.add_entry(entry(99, 999, "orfao.txt", false));

        let orphan = investigation
            .entries()
            .iter()
            .find(|e| e.inode_number() == 99)
            .unwrap();

        assert_eq!(investigation.resolve_path(orphan), "/orfao.txt");
    }

    #[test]
    fn converts_to_forensic_model() {
        let investigation = nested_investigation();

        let model = investigation.to_forensic_model(Some("imagem.ext4".to_string()));

        assert_eq!(model.source().filesystem(), ForensicFilesystem::Ext4);
        assert_eq!(model.source().image(), Some("imagem.ext4"));
        assert_eq!(model.len(), 3);

        let arquivo = &model.entries()[2];

        assert_eq!(arquivo.identity.path, "/nivel1/arquivo.txt");
        assert_eq!(arquivo.identity.kind, ForensicEntryKind::File);
    }
}

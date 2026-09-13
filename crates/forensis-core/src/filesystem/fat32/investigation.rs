//! FAT32 investigation walk.
//!
//! FAT32 keeps its hierarchy in directory entries rather than inodes,
//! and deleted files are marked by overwriting the first byte of their
//! directory entry with `0xE5`. The walk below visits every reachable
//! directory and also descends into deleted directories, so deleted
//! entries keep their recovered names and parent chain.
//!
//! Content of deleted files is recovered by following the residual FAT
//! chain, which is left intact when a file is deleted, up to the
//! number of clusters implied by the recorded file size.

use std::collections::{HashSet, VecDeque};

use super::directory::parse_directory_entries;
use super::Fat32Reader;
use crate::filesystem::fat32::directory::Fat32DirectoryEntry;
use crate::filesystem::fat32::Fat32InvestigationEntry;

use crate::forensic::{ForensicEntry, ForensicFilesystem, ForensicModel, ForensicSource};
use crate::result::Result;
use crate::traits::Readable;

/// Internal result of the FAT32 investigation.
///
/// This structure belongs exclusively to the FAT32 layer. The public
/// filesystem output is converted into `ForensicModel`.
#[derive(Debug)]
pub struct Fat32Investigation {
    entries: Vec<Fat32InvestigationEntry>,

    /// Number of directory clusters actually parsed.
    records: u64,

    /// Number of bytes contained in one cluster.
    bytes_per_cluster: u64,

    /// Number of 512-byte sectors contained in one cluster.
    sectors_per_cluster: u64,

    /// Partition-relative sector where the data region starts.
    first_data_sector: u64,
}

impl Fat32Investigation {
    /// Creates an empty FAT32 investigation.
    pub fn new(bytes_per_cluster: u64, sectors_per_cluster: u64, first_data_sector: u64) -> Self {
        Self {
            entries: Vec::new(),
            records: 0,
            bytes_per_cluster,
            sectors_per_cluster,
            first_data_sector,
        }
    }

    /// Adds an entry to the FAT32 investigation.
    pub fn add_entry(&mut self, entry: Fat32InvestigationEntry) {
        self.entries.push(entry);
    }

    /// Increments the number of parsed directory clusters.
    pub fn increment_records(&mut self) {
        self.records += 1;
    }

    /// Returns the number of discovered entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of parsed directory clusters.
    pub fn record_count(&self) -> u64 {
        self.records
    }

    /// Returns the cluster size.
    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_cluster
    }

    /// Returns all FAT32 investigation entries.
    pub fn entries(&self) -> &[Fat32InvestigationEntry] {
        &self.entries
    }

    /// Resolves the absolute path of a FAT32 entry.
    ///
    /// The path is built by walking the entry, its parent, its
    /// grandparent and so on up to the root.
    fn resolve_path(&self, entry: &Fat32InvestigationEntry) -> String {
        /*
         * The root directory is recognized by pointing to itself,
         * exactly as EXT4 and NTFS roots are recognized.
         */
        if entry.is_directory() && entry.object_id() == entry.parent_id() {
            return "/".to_string();
        }

        let mut components = Vec::new();

        let mut current_id = entry.object_id();

        let mut visited = Vec::new();

        loop {
            if visited.contains(&current_id) {
                break;
            }

            visited.push(current_id);

            let current = match self
                .entries
                .iter()
                .find(|candidate| candidate.object_id() == current_id)
            {
                Some(value) => value,

                None => break,
            };

            if current.object_id() == current.parent_id() {
                break;
            }

            components.push(current.name().to_string());

            current_id = current.parent_id();
        }

        components.reverse();

        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    /// Converts the internal FAT32 result into the filesystem-independent
    /// forensic model.
    pub fn to_forensic_model(&self, image: Option<String>) -> ForensicModel {
        let entries: Vec<ForensicEntry> = self
            .entries
            .iter()
            .map(|entry| {
                let mut forensic_entry = entry.to_forensic_entry(
                    self.bytes_per_cluster,
                    self.sectors_per_cluster,
                    self.first_data_sector,
                );

                forensic_entry.identity.path = self.resolve_path(entry);

                forensic_entry
            })
            .collect();

        ForensicModel::new(
            ForensicSource::new(image, ForensicFilesystem::Fat32),
            self.records,
            entries,
        )
    }
}

/// Investigates a FAT32 filesystem.
///
/// The walk starts at the root directory (whose cluster is given by
/// the boot sector) and recursively descends into every directory,
/// including deleted ones.
pub fn investigate_filesystem<R: Readable>(
    reader: &mut Fat32Reader<R>,
) -> Result<Fat32Investigation> {
    let boot = reader.boot();

    let bytes_per_cluster = boot.cluster_size();

    let sectors_per_cluster = boot.sectors_per_cluster_u64();

    let first_data_sector = boot.first_data_sector();

    let root_cluster = boot.root_cluster();

    let total_clusters = boot.total_clusters();

    let mut investigation =
        Fat32Investigation::new(bytes_per_cluster, sectors_per_cluster, first_data_sector);

    let mut visited_dirs: HashSet<u32> = HashSet::new();

    // Next object id to assign (1 is reserved for the root).
    let mut next_id: u64 = 1;

    // (directory cluster, parent object id, directory name).
    let mut queue: VecDeque<(u32, u64, String)> = VecDeque::new();

    queue.push_back((root_cluster, next_id, "/".to_string()));

    visited_dirs.insert(root_cluster);

    while let Some((cluster, parent_id, name)) = queue.pop_front() {
        if !walk_directory(
            reader,
            &mut investigation,
            &mut visited_dirs,
            &mut queue,
            &mut next_id,
            cluster,
            parent_id,
            name,
            total_clusters,
        )? {
            continue;
        }
    }

    Ok(investigation)
}

/// Parses one directory (its whole chain) and registers the directory
/// entry plus every subordinate entry.
#[allow(clippy::too_many_arguments)]
fn walk_directory<R: Readable>(
    reader: &mut Fat32Reader<R>,
    investigation: &mut Fat32Investigation,
    visited_dirs: &mut HashSet<u32>,
    queue: &mut VecDeque<(u32, u64, String)>,
    next_id: &mut u64,
    cluster: u32,
    parent_id: u64,
    name: String,
    total_clusters: u64,
) -> Result<bool> {
    let chain = reader.walk_chain(cluster, total_clusters)?;

    if chain.is_empty() {
        return Ok(false);
    }

    let object_id = *next_id;

    *next_id += 1;

    investigation.add_entry(Fat32InvestigationEntry::new(
        object_id,
        parent_id,
        name,
        true,
        false,
        false,
        0,
        0x10,
        cluster,
        chain.clone(),
    ));

    for directory_cluster in &chain {
        let buffer = reader.read_directory_cluster(*directory_cluster)?;

        investigation.increment_records();

        for parsed in parse_directory_entries(&buffer) {
            register_entry(
                reader,
                investigation,
                visited_dirs,
                queue,
                next_id,
                object_id,
                &parsed,
            );
        }
    }

    Ok(true)
}

/// Registers one parsed directory entry found inside a directory.
///
/// Files keep the recorded size and a chain resolved from the FAT (the
/// residual chain for deleted files). Directories are enqueued so their
/// own content gets scanned.
fn register_entry<R: Readable>(
    reader: &mut Fat32Reader<R>,
    investigation: &mut Fat32Investigation,
    visited_dirs: &mut HashSet<u32>,
    queue: &mut VecDeque<(u32, u64, String)>,
    next_id: &mut u64,
    parent_id: u64,
    parsed: &Fat32DirectoryEntry,
) {
    if parsed.is_volume_label() {
        investigation.add_entry(Fat32InvestigationEntry::new(
            *next_id,
            parent_id,
            parsed.name().to_string(),
            false,
            true,
            false,
            0,
            parsed.attributes(),
            0,
            Vec::new(),
        ));

        *next_id += 1;

        return;
    }

    if parsed.is_directory() {
        /*
         * Directories are visited later. The cluster guard prevents
         * a deleted directory whose chain was reused by a live one
         * from being parsed twice.
         */
        if parsed.cluster() >= 2 && visited_dirs.insert(parsed.cluster()) {
            queue.push_back((parsed.cluster(), parent_id, parsed.name().to_string()));
        }

        return;
    }

    let (cluster, chain) = resolve_file_chain(reader, investigation, parsed);

    investigation.add_entry(Fat32InvestigationEntry::new(
        *next_id,
        parent_id,
        parsed.name().to_string(),
        false,
        false,
        parsed.is_deleted(),
        parsed.size() as u64,
        parsed.attributes(),
        cluster,
        chain,
    ));

    *next_id += 1;
}

/// Resolves the FAT chain of a file entry.
///
/// Live and deleted files both follow the chain recorded in the FAT.
/// The number of followed clusters is bounded by the recorded size so
/// leftover chain data is not included in the recovered content.
fn resolve_file_chain<R: Readable>(
    reader: &mut Fat32Reader<R>,
    investigation: &Fat32Investigation,
    parsed: &Fat32DirectoryEntry,
) -> (u32, Vec<u32>) {
    let cluster = parsed.cluster();

    if cluster < 2 || parsed.size() == 0 {
        return (cluster, Vec::new());
    }

    let clusters_needed = u64::from(parsed.size()).div_ceil(investigation.bytes_per_cluster());

    let chain = reader
        .walk_chain(cluster, clusters_needed.max(1))
        .unwrap_or_default();

    (cluster, chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::{ForensicEntryKind, ForensicFilesystem};

    fn entry(
        object_id: u64,
        parent_id: u64,
        name: &str,
        is_directory: bool,
    ) -> Fat32InvestigationEntry {
        Fat32InvestigationEntry::new(
            object_id,
            parent_id,
            name.to_string(),
            is_directory,
            false,
            false,
            0,
            0x20,
            2,
            vec![2],
        )
    }

    fn nested_investigation() -> Fat32Investigation {
        let mut investigation = Fat32Investigation::new(4096, 8, 1056);

        investigation.add_entry(entry(1, 1, "/", true));
        investigation.add_entry(entry(2, 1, "nivel1", true));
        investigation.add_entry(entry(3, 2, "arquivo.txt", false));

        investigation
    }

    #[test]
    fn root_resolves_to_root_path() {
        let investigation = nested_investigation();

        let root = investigation
            .entries()
            .iter()
            .find(|e| e.object_id() == 1)
            .unwrap();

        assert_eq!(investigation.resolve_path(root), "/");
    }

    #[test]
    fn nested_entry_resolves_full_path() {
        let investigation = nested_investigation();

        let arquivo = investigation
            .entries()
            .iter()
            .find(|e| e.object_id() == 3)
            .unwrap();

        assert_eq!(investigation.resolve_path(arquivo), "/nivel1/arquivo.txt");
    }

    #[test]
    fn cycle_produces_safe_path() {
        let mut investigation = nested_investigation();

        investigation.add_entry(entry(10, 10, "corrompido", false));

        let corrupted = investigation
            .entries()
            .iter()
            .find(|e| e.object_id() == 10)
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
            .find(|e| e.object_id() == 99)
            .unwrap();

        assert_eq!(investigation.resolve_path(orphan), "/orfao.txt");
    }

    #[test]
    fn converts_to_forensic_model() {
        let investigation = nested_investigation();

        let model = investigation.to_forensic_model(Some("imagem.fat32".to_string()));

        assert_eq!(model.source().filesystem(), ForensicFilesystem::Fat32);
        assert_eq!(model.source().image(), Some("imagem.fat32"));
        assert_eq!(model.len(), 3);

        let arquivo = &model.entries()[2];

        assert_eq!(arquivo.identity.path, "/nivel1/arquivo.txt");
        assert_eq!(arquivo.identity.kind, ForensicEntryKind::File);
    }
}

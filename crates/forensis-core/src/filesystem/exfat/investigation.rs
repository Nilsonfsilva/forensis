//! exFAT investigation walk.
//!
//! exFAT stores the hierarchy in directory records (file + stream + name
//! entries) and marks deletion by clearing the in-use bit of every entry
//! in the record. The walk below visits every reachable directory caller
//! chain, including deleted directories, so deleted entries keep their
//! recovered names, timestamps and parent chain.
//!
//! Content of deleted files is recovered by following the residual FAT
//! chain, which is left intact when a file is deleted, up to the number
//! of clusters implied by the recorded data length.

use std::collections::{HashSet, VecDeque};

use super::directory::{parse_directory_entries, ExFatEntryKind};
use super::{ExFatInvestigationEntry, ExFatReader};
use crate::forensic::{ForensicEntry, ForensicFilesystem, ForensicModel, ForensicSource};
use crate::result::Result;
use crate::traits::Readable;

/// Internal result of the exFAT investigation.
///
/// This structure belongs exclusively to the exFAT layer. The public
/// filesystem output is converted into `ForensicModel`.
#[derive(Debug)]
pub struct ExFatInvestigation {
    entries: Vec<ExFatInvestigationEntry>,

    /// Number of directory clusters actually parsed.
    records: u64,

    /// Number of bytes contained in one cluster.
    bytes_per_cluster: u64,

    /// Number of 512-byte sectors contained in one cluster.
    sectors_per_cluster: u64,

    /// Partition-relative sector where the data region starts.
    first_data_sector: u64,
}

impl ExFatInvestigation {
    /// Creates an empty exFAT investigation.
    pub fn new(bytes_per_cluster: u64, sectors_per_cluster: u64, first_data_sector: u64) -> Self {
        Self {
            entries: Vec::new(),
            records: 0,
            bytes_per_cluster,
            sectors_per_cluster,
            first_data_sector,
        }
    }

    /// Adds an entry to the exFAT investigation.
    pub fn add_entry(&mut self, entry: ExFatInvestigationEntry) {
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

    /// Returns all exFAT investigation entries.
    pub fn entries(&self) -> &[ExFatInvestigationEntry] {
        &self.entries
    }

    /// Resolves the absolute path of an exFAT entry.
    ///
    /// The path is built by walking the entry, its parent, its
    /// grandparent and so on up to the root.
    fn resolve_path(&self, entry: &ExFatInvestigationEntry) -> String {
        /*
         * The root directory is recognized by pointing to itself,
         * exactly as EXT4, NTFS and FAT32 roots are recognized.
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

    /// Converts the internal exFAT result into the filesystem-independent
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
            ForensicSource::new(image, ForensicFilesystem::ExFat),
            self.records,
            entries,
        )
    }
}

/// Investigates an exFAT filesystem.
///
/// The walk starts at the root directory (whose cluster is given by the
/// boot sector) and recursively descends into every directory,
/// including deleted ones.
pub fn investigate_filesystem<R: Readable>(
    reader: &mut ExFatReader<R>,
) -> Result<ExFatInvestigation> {
    let boot = reader.boot();

    let bytes_per_cluster = boot.cluster_size();

    let sectors_per_cluster = boot.sectors_per_cluster_u64();

    let first_data_sector = boot.first_data_sector();

    let root_cluster = boot.root_directory_cluster();

    let cluster_count = boot.cluster_count();

    let mut investigation =
        ExFatInvestigation::new(bytes_per_cluster, sectors_per_cluster, first_data_sector);

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
            cluster_count,
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
    reader: &mut ExFatReader<R>,
    investigation: &mut ExFatInvestigation,
    visited_dirs: &mut HashSet<u32>,
    queue: &mut VecDeque<(u32, u64, String)>,
    next_id: &mut u64,
    cluster: u32,
    parent_id: u64,
    name: String,
    cluster_count: u32,
) -> Result<bool> {
    let chain = reader.walk_chain(cluster, cluster_count as u64)?;

    if chain.is_empty() {
        return Ok(false);
    }

    let object_id = *next_id;

    *next_id += 1;

    investigation.add_entry(ExFatInvestigationEntry::new(
        object_id,
        parent_id,
        name,
        ExFatEntryKind::Directory,
        false,
        0,
        0x10,
        cluster,
        chain.clone(),
        None,
        None,
        None,
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
/// Files keep the recorded timestamps and a chain resolved from the FAT
/// (the residual chain for deleted files). Directories are enqueued so
/// their own content gets scanned.
fn register_entry<R: Readable>(
    reader: &mut ExFatReader<R>,
    investigation: &mut ExFatInvestigation,
    visited_dirs: &mut HashSet<u32>,
    queue: &mut VecDeque<(u32, u64, String)>,
    next_id: &mut u64,
    parent_id: u64,
    parsed: &super::directory::ExFatDirectoryEntry,
) {
    if parsed.is_volume_label() {
        investigation.add_entry(ExFatInvestigationEntry::new(
            *next_id,
            parent_id,
            parsed.name().to_string(),
            ExFatEntryKind::VolumeLabel,
            false,
            0,
            parsed.attributes(),
            0,
            Vec::new(),
            None,
            None,
            None,
        ));

        *next_id += 1;

        return;
    }

    if parsed.is_system() {
        investigation.add_entry(ExFatInvestigationEntry::new(
            *next_id,
            parent_id,
            parsed.name().to_string(),
            parsed.kind(),
            false,
            0,
            parsed.attributes(),
            parsed.cluster(),
            Vec::new(),
            None,
            None,
            None,
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

    investigation.add_entry(ExFatInvestigationEntry::new(
        *next_id,
        parent_id,
        parsed.name().to_string(),
        ExFatEntryKind::File,
        parsed.is_deleted(),
        parsed.size(),
        parsed.attributes(),
        cluster,
        chain,
        parsed.created_at(),
        parsed.modified_at(),
        parsed.accessed_at(),
    ));

    *next_id += 1;
}

/// Resolves the FAT chain of a file entry.
///
/// Live and deleted files both follow the chain recorded in the FAT.
/// The number of followed clusters is bounded by the recorded size so
/// leftover chain data is not included in the recovered content.
fn resolve_file_chain<R: Readable>(
    reader: &mut ExFatReader<R>,
    investigation: &ExFatInvestigation,
    parsed: &super::directory::ExFatDirectoryEntry,
) -> (u32, Vec<u32>) {
    let cluster = parsed.cluster();

    if cluster < 2 || parsed.size() == 0 {
        return (cluster, Vec::new());
    }

    let clusters_needed = parsed.size().div_ceil(investigation.bytes_per_cluster());

    let chain = reader
        .walk_chain(cluster, clusters_needed.max(1))
        .unwrap_or_default();

    (cluster, chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::{ForensicEntryKind, ForensicFilesystem};

    fn entry(object_id: u64, parent_id: u64, name: &str) -> ExFatInvestigationEntry {
        ExFatInvestigationEntry::new(
            object_id,
            parent_id,
            name.to_string(),
            ExFatEntryKind::File,
            false,
            0,
            0x20,
            2,
            vec![2],
            None,
            None,
            None,
        )
    }

    fn nested_investigation() -> ExFatInvestigation {
        let mut investigation = ExFatInvestigation::new(4096, 8, 2176);

        // Root and level directories are marked as directories so the
        // path resolution treats them as hierarchy nodes.
        let root = ExFatInvestigationEntry::new(
            1,
            1,
            "/".to_string(),
            ExFatEntryKind::Directory,
            false,
            0,
            0x10,
            2,
            vec![2],
            None,
            None,
            None,
        );
        let nivel1 = ExFatInvestigationEntry::new(
            2,
            1,
            "nivel1".to_string(),
            ExFatEntryKind::Directory,
            false,
            0,
            0x10,
            3,
            vec![3],
            None,
            None,
            None,
        );

        investigation.add_entry(root);
        investigation.add_entry(nivel1);
        investigation.add_entry(entry(3, 2, "arquivo.txt"));

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

        investigation.add_entry(entry(10, 10, "corrompido"));

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

        investigation.add_entry(entry(99, 999, "orfao.txt"));

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

        let model = investigation.to_forensic_model(Some("imagem.exfat".to_string()));

        assert_eq!(model.source().filesystem(), ForensicFilesystem::ExFat);
        assert_eq!(model.source().image(), Some("imagem.exfat"));
        assert_eq!(model.len(), 3);

        let arquivo = &model.entries()[2];

        assert_eq!(arquivo.identity.path, "/nivel1/arquivo.txt");
        assert_eq!(arquivo.identity.kind, ForensicEntryKind::File);
    }
}

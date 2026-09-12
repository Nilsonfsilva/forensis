use super::NtfsDirectory;

use crate::forensic::{ForensicEntry, ForensicFilesystem, ForensicModel, ForensicSource};

use crate::result::Result;

use super::{InvestigationEntry, MftParser, MftRecord, ParsedMftRecord};

/// Internal result of the NTFS investigation.
///
/// This structure belongs exclusively to the NTFS layer.
///
/// It may know about:
///
/// - MFT
/// - FILE_NAME
/// - DATA
/// - INDEX_ROOT
/// - INDEX_ALLOCATION
/// - NTFS directories
/// - MFT records
/// - InvestigationEntry
/// - NTFS volume geometry
///
/// The application must not consume this structure directly.
///
/// The public filesystem output is converted into
/// `ForensicModel`.
#[derive(Debug, Default)]
pub struct Investigation {
    entries: Vec<InvestigationEntry>,
    records: Vec<ParsedMftRecord>,

    /// NTFS directories discovered during the investigation.
    ///
    /// The structure keeps the structural representation of the
    /// INDEX_ROOT without dropping the original INDEX_ENTRY.
    directories: Vec<NtfsDirectory>,

    /// Number of sectors contained in one NTFS cluster.
    ///
    /// This information belongs to the volume geometry and,
    /// therefore, remains inside the NTFS layer.
    sectors_per_cluster: u64,
}

impl Investigation {
    /// Creates an empty NTFS investigation.
    ///
    /// `sectors_per_cluster` comes directly from the boot sector
    /// of the NTFS volume.
    pub fn new(sectors_per_cluster: u64) -> Self {
        Self {
            entries: Vec::new(),
            records: Vec::new(),
            directories: Vec::new(),
            sectors_per_cluster,
        }
    }

    /// Adds an entry to the NTFS investigation.
    pub fn add_entry(&mut self, entry: InvestigationEntry) {
        self.entries.push(entry);
    }

    /// Adds an NTFS directory to the investigation.
    ///
    /// The directory is kept in the NTFS-specific layer.
    ///
    /// The INDEX_ROOT structure and its INDEX_ENTRY are preserved
    /// in `directories`.
    ///
    /// The INDEX_ENTRY are not converted again into
    /// InvestigationEntry here because the FILE_NAME belonging
    /// to the MFT records were already processed by
    /// `add_mft_record()`.
    ///
    /// This separation prevents the same object from being added
    /// twice to the public collection of entries.
    pub fn add_directory(&mut self, directory: &NtfsDirectory) -> Result<()> {
        /*
         * ---------------------------------------------------------
         * STORE DIRECTORY STRUCTURE
         * ---------------------------------------------------------
         *
         * The directory remains available inside the
         * NTFS investigation.
         *
         * Its INDEX_ENTRY remain fully preserved for the
         * later stages of directory hierarchy analysis.
         */
        self.directories.push(directory.clone());

        Ok(())
    }

    /// Adds all entries of an NTFS directory.
    ///
    /// This method remains available as an explicit
    /// conversion operation for an already existing directory.
    ///
    /// Unlike `add_directory()`, it does not store
    /// the directory structure again.
    ///
    /// The explicit conversion may be used in the future
    /// when the investigation needs to materialize the
    /// INDEX_ENTRY as independent evidence.
    pub fn add_directory_entries(&mut self, directory: &NtfsDirectory) -> Result<()> {
        for entry in &directory.entries {
            let file_reference = entry.mft_record();

            if let Ok(file_name) = entry.file_name() {
                self.entries.push(InvestigationEntry::from_file_name(
                    file_reference,
                    &file_name,
                ));
            }
        }

        Ok(())
    }

    /// Adds an already interpreted MFT record.
    ///
    /// FILE_NAME provides:
    ///
    /// - name
    /// - parent directory
    /// - flags
    ///
    /// DATA provides:
    ///
    /// - real file size
    /// - allocated size
    /// - data runs
    ///
    /// MFT flags provide:
    ///
    /// - record allocation state
    pub fn add_mft_record(&mut self, record: &ParsedMftRecord) {
        for file_name in &record.file_names {
            self.entries
                .push(InvestigationEntry::from_file_name_and_data(
                    record.index,
                    file_name,
                    record.data.as_ref(),
                    record.mft_flags,
                ));
        }
    }

    /// Processes an MFT record.
    ///
    /// The parser interprets the record attributes.
    ///
    /// FILE_NAME is converted into an investigation entry.
    ///
    /// INDEX_ROOT is converted into an NtfsDirectory and stored
    /// in the investigation.
    ///
    /// The INDEX_ENTRY remain in the directory-specific structure
    /// and are not added again to the main
    /// InvestigationEntry collection.
    pub fn process_mft_record(&mut self, record: &mut MftRecord) -> Result<()> {
        let parsed = MftParser::parse(record)?;

        /*
         * ---------------------------------------------------------
         * MFT / FILE_NAME
         * ---------------------------------------------------------
         *
         * The FILE_NAME found directly in the MFT record
         * are added to the investigation.
         *
         * This is the main source of the InvestigationEntry.
         */
        self.add_mft_record(&parsed);

        /*
         * ---------------------------------------------------------
         * INDEX_ROOT
         * ---------------------------------------------------------
         *
         * If the record has an INDEX_ROOT, it represents the
         * initial structure of a directory index.
         *
         * The structure is converted into an NtfsDirectory and
         * stored in the investigation.
         *
         * The INDEX_ENTRY are not converted again into
         * InvestigationEntry, because this would duplicate the
         * objects already obtained through the MFT FILE_NAME.
         *
         * We do not depend on the number of entries to create
         * the directory. An empty INDEX_ROOT is still a valid
         * structure and may indicate that the rest of the
         * index is in INDEX_ALLOCATION.
         */
        if let Some(index_root) = &parsed.index_root {
            let directory = NtfsDirectory::from_index_root(parsed.index, index_root)?;

            self.add_directory(&directory)?;
        }

        /*
         * The interpreted MFT record is preserved for the
         * next stages of the investigation.
         */
        self.records.push(parsed);

        Ok(())
    }

    /// Resolves the absolute path of an NTFS entry.
    ///
    /// The resolution happens exclusively inside the NTFS
    /// layer, because only this layer knows the semantics of
    /// `parent_mft_record`.
    ///
    /// The path is built by walking the entry,
    /// its parent, its grandparent and so on up to the root.
    ///
    /// The set of entries is used to locate each
    /// parent record.
    fn resolve_path(&self, entry: &InvestigationEntry) -> String {
        /*
         * Record 5 is the conventional NTFS root.
         *
         * However, we do not depend exclusively on it:
         * we also recognize an entry whose parent points to
         * itself as the root.
         */
        if entry.mft_record == entry.parent_mft_record {
            return "/".to_string();
        }

        let mut components = Vec::new();

        let mut current_record = entry.mft_record;

        let mut visited = Vec::new();

        loop {
            /*
             * Protection against corruption or a cycle in the hierarchy.
             *
             * Forensic evidence must not allow a corrupted
             * structure to cause an infinite loop.
             */
            if visited.contains(&current_record) {
                break;
            }

            visited.push(current_record);

            let current = match self
                .entries
                .iter()
                .find(|candidate| candidate.mft_record == current_record)
            {
                Some(value) => value,

                None => break,
            };

            /*
             * The root must not appear as a component of the path.
             */
            if current.mft_record == current.parent_mft_record {
                break;
            }

            components.push(current.name.clone());

            current_record = current.parent_mft_record;
        }

        components.reverse();

        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    /// Converts the internal NTFS result into the
    /// filesystem-independent forensic model.
    ///
    /// The volume geometry remains encapsulated in the
    /// NTFS investigation.
    ///
    /// After this conversion, the application no longer needs
    /// to know about `InvestigationEntry`, `ParsedMftRecord`,
    /// `NtfsDirectory`, `sectors_per_cluster` or other
    /// NTFS-specific structures.
    pub fn to_forensic_model(&self, image: Option<String>) -> ForensicModel {
        let entries: Vec<ForensicEntry> = self
            .entries
            .iter()
            .map(|entry| {
                let mut forensic_entry = entry.to_forensic_entry(self.sectors_per_cluster);

                /*
                 * The path is resolved while we are still
                 * inside the NTFS layer.
                 */
                forensic_entry.identity.path = self.resolve_path(entry);

                forensic_entry
            })
            .collect();

        ForensicModel::new(
            ForensicSource::new(image, ForensicFilesystem::Ntfs),
            self.record_count() as u64,
            entries,
        )
    }

    /// Returns all child entries of a given
    /// MFT record.
    pub fn children_of(&self, parent_mft_record: u64) -> Vec<&InvestigationEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.parent_mft_record == parent_mft_record)
            .collect()
    }

    /// Returns all NTFS entries found.
    pub fn entries(&self) -> &[InvestigationEntry] {
        &self.entries
    }

    /// Returns all NTFS directories found.
    pub fn directories(&self) -> &[NtfsDirectory] {
        &self.directories
    }

    /// Returns all interpreted MFT records.
    pub fn records(&self) -> &[ParsedMftRecord] {
        &self.records
    }

    /// Returns the number of discovered entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of discovered directories.
    pub fn directory_count(&self) -> usize {
        self.directories.len()
    }

    /// Returns the number of processed MFT records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

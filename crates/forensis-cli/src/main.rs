use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use forensis_app::recovery::HashComparison;

use forensis_app::{
    discover_sources, inspect_image, inspect_image_with_progress, next_recovery_ticket,
    recover_all_from_result, recover_object_from_result, recover_objects_from_result,
    EvidenceSource, ForensicEntry, ForensicEntryKind, ForensicModel, ForensicStatus, ForensicTree,
    ForensicTreeNode, InspectionResult, ProgressEvent, ProgressPhase, ProgressReporter,
    ProgressUnit, RecoveryFilter,
};

#[derive(Parser, Debug)]
#[command(
    name = "forensis",
    version,
    about = "Digital forensic investigation framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Inspects a disk image.
    ///
    /// Use --status to filter forensic objects by status.
    Inspect {
        /// Path to the disk image.
        image: PathBuf,

        /// Displays detailed information about a forensic object.
        #[arg(long)]
        detail: Option<u64>,

        /// Filters forensic objects by status.
        ///
        /// Accepted values:
        /// normal, system, deleted, carved, inconsistent, unknown
        #[arg(long, value_enum)]
        status: Option<StatusFilter>,
    },

    /// Displays the filesystem-independent forensic tree.
    Tree {
        /// Path to the disk image.
        image: PathBuf,

        /// Optional path inside the filesystem.
        path: Option<String>,
    },

    /// Recovers forensic objects from a disk image.
    Recover {
        #[command(subcommand)]
        command: RecoverCommand,
    },
}

#[derive(Subcommand, Debug)]
enum RecoverCommand {
    /// Selects and recovers objects marked as deleted.
    Deleted {
        /// Path to the disk image.
        image: PathBuf,

        /// Directory where recovered files will be written.
        #[arg(short, long)]
        output: PathBuf,

        /// Object IDs to recover (skips interactive selection).
        #[arg(long)]
        object: Vec<u64>,
    },

    /// Selects and recovers objects marked as normal (live files).
    Normal {
        /// Path to the disk image.
        image: PathBuf,

        /// Directory where recovered files will be written.
        #[arg(short, long)]
        output: PathBuf,

        /// Object IDs to recover (skips interactive selection).
        #[arg(long)]
        object: Vec<u64>,
    },

    /// Runs all currently available recovery methods.
    ///
    /// At this stage this includes physical recovery of
    /// deleted and normal filesystem objects.
    All {
        /// Path to the disk image.
        image: PathBuf,

        /// Directory where recovered files will be written.
        #[arg(short, long)]
        output: PathBuf,

        /// Object IDs to recover (skips the full scope).
        #[arg(long)]
        object: Vec<u64>,
    },
}

/// Status filter used by the inspect command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StatusFilter {
    /// Normal forensic objects.
    Normal,

    /// Filesystem system objects.
    System,

    /// Deleted forensic objects.
    Deleted,

    /// Recovered or carved objects.
    Carved,

    /// Objects with inconsistent forensic information.
    Inconsistent,

    /// Objects with unknown status.
    Unknown,
}

impl StatusFilter {
    fn matches(self, status: ForensicStatus) -> bool {
        match self {
            Self::Normal => status == ForensicStatus::Normal,

            Self::System => status == ForensicStatus::System,

            Self::Deleted => status == ForensicStatus::Deleted,

            Self::Carved => status == ForensicStatus::Carved,

            Self::Inconsistent => status == ForensicStatus::Inconsistent,

            Self::Unknown => status == ForensicStatus::Unknown,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::System => "System",
            Self::Deleted => "Deleted",
            Self::Carved => "Carved / Recovered",
            Self::Inconsistent => "Inconsistent",
            Self::Unknown => "Unknown",
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Command::Inspect {
            image,
            detail,
            status,
        } => {
            let source = select_source(&image)?;

            let image = source.path().to_path_buf();

            inspect_image_command(image, detail, status)?;
        }

        Command::Tree { image, path } => {
            tree_command(image, path)?;
        }

        Command::Recover { command } => {
            recover_command(command)?;
        }
    }

    Ok(())
}

/*
 * ---------------------------------------------------------
 * INSPECT COMMAND
 * ---------------------------------------------------------
 */

fn select_source(path: &Path) -> Result<EvidenceSource> {
    let sources = discover_sources(path)?;

    if sources.len() == 1 {
        return Ok(sources[0].clone());
    }

    const RESET: &str = "\x1b[0m";
    const DARK_BLUE: &str = "\x1b[93m";
    const LIGHT_BLUE: &str = "\x1b[1;34m";
    const YELLOW: &str = "\x1b[92m";

    println!();
    println!("Forensis");
    println!("========");
    println!();

    println!(
        "{}Available sources in {}:{}",
        DARK_BLUE,
        path.display(),
        RESET
    );

    println!();

    let block_devices: Vec<(usize, &EvidenceSource)> = sources
        .iter()
        .enumerate()
        .filter(|(_, source)| source.is_block_device())
        .collect();

    let partitions: Vec<(usize, &EvidenceSource)> = sources
        .iter()
        .enumerate()
        .filter(|(_, source)| source.is_partition())
        .collect();

    let disk_images: Vec<(usize, &EvidenceSource)> = sources
        .iter()
        .enumerate()
        .filter(|(_, source)| source.is_disk_image())
        .collect();

    if !block_devices.is_empty() {
        println!("{}Devices:{}", DARK_BLUE, RESET);

        for (index, device) in &block_devices {
            println!(
                "  {}[{}] {}{}",
                LIGHT_BLUE,
                index + 1,
                device.path().display(),
                RESET
            );

            let device_name = device.path().file_name().map(|name| name.to_string_lossy());

            if let Some(device_name) = device_name {
                let device_name = device_name.as_ref();

                let device_partitions: Vec<(usize, &EvidenceSource)> = partitions
                    .iter()
                    .copied()
                    .filter(|(_, partition)| {
                        let partition_name = partition
                            .path()
                            .file_name()
                            .map(|name| name.to_string_lossy());

                        match partition_name {
                            Some(partition_name) => partition_name.starts_with(device_name),

                            None => false,
                        }
                    })
                    .collect();

                if !device_partitions.is_empty() {
                    println!("        {}Partitions:{}", DARK_BLUE, RESET);

                    for (partition_index, partition) in device_partitions {
                        println!(
                            "          {}[{}] {}{}",
                            LIGHT_BLUE,
                            partition_index + 1,
                            partition.path().display(),
                            RESET
                        );
                    }
                }
            }

            println!();
        }
    }

    if !disk_images.is_empty() {
        println!("{}Disk images:{}", DARK_BLUE, RESET);

        for (index, image) in disk_images {
            println!(
                "  {}[{}] {}{}",
                LIGHT_BLUE,
                index + 1,
                image.path().display(),
                RESET
            );
        }

        println!();
    }

    print!("{}Choose a source [1-{}]: {}", YELLOW, sources.len(), RESET);

    io::stdout().flush()?;

    let mut input = String::new();

    io::stdin().read_line(&mut input)?;

    let selection: usize = input
        .trim()
        .parse()
        .map_err(|_| anyhow!("Invalid selection."))?;

    if selection == 0 || selection > sources.len() {
        return Err(anyhow!("Selection out of range."));
    }

    sources
        .get(selection - 1)
        .cloned()
        .ok_or_else(|| anyhow!("Selected source not found."))
}

/// Reports filesystem investigation progress to the terminal.
struct CliProgressReporter;

impl ProgressReporter for CliProgressReporter {
    fn report(&self, event: ProgressEvent) {
        match event.phase {
            ProgressPhase::ReadingMetadata => {
                print!("\rInvestigating filesystem: reading metadata...");

                let _ = io::stdout().flush();
            }

            ProgressPhase::ReadingData => {
                print!("\rInvestigating filesystem: reading data...");

                let _ = io::stdout().flush();
            }

            ProgressPhase::ProcessingRecords => {
                let unit = match event.unit {
                    ProgressUnit::MftRecords => "MFT records",
                    ProgressUnit::Records => "records",
                    ProgressUnit::Inodes => "inodes",
                    ProgressUnit::DirectoryClusters => "directory clusters",
                    ProgressUnit::Bytes => "bytes",
                    ProgressUnit::Objects => "objects",
                    ProgressUnit::None => "units",
                };

                if let Some(total) = event.total {
                    let percentage = event.percentage().unwrap_or(0);

                    print!(
                        "\rInvestigating filesystem: {:3}% ({}/{} {})",
                        percentage, event.current, total, unit
                    );
                } else {
                    print!("\rInvestigating filesystem: {} {}", event.current, unit);
                }

                let _ = io::stdout().flush();
            }

            ProgressPhase::BuildingEntries => {
                print!("\rInvestigating filesystem: building forensic entries...");

                let _ = io::stdout().flush();
            }

            ProgressPhase::Recovering => {
                let percentage = event.percentage().unwrap_or(0);

                print!(
                    "\rRecovering objects: {:3}% ({} of {})",
                    percentage,
                    event.current,
                    event.total.unwrap_or(0)
                );

                let _ = io::stdout().flush();
            }

            ProgressPhase::DetectingFilesystem => {
                print!("\rDetecting filesystem...");

                let _ = io::stdout().flush();
            }

            ProgressPhase::Completed => {
                println!("\rCompleted: 100%");

                let _ = io::stdout().flush();
            }
        }
    }
}

fn inspect_image_command(
    path: PathBuf,
    detail: Option<u64>,
    status: Option<StatusFilter>,
) -> Result<()> {
    let reporter = CliProgressReporter;

    let result = inspect_image_with_progress(&path, &reporter)?;

    /*
     * --detail keeps priority.
     *
     * The --status filter is intended for listing
     * objects discovered during the investigation.
     */
    if let Some(object_id) = detail {
        println!("{}", format_detail(&result, object_id,));

        return Ok(());
    }

    match status {
        Some(status) => {
            println!("{}", format_status_filter(&result, status,));
        }

        None => {
            println!("{}", format_inspection(&result,));
        }
    }

    Ok(())
}

fn format_status_filter(result: &InspectionResult, status: StatusFilter) -> String {
    let mut output = String::new();

    output.push_str("Forensis\n");

    output.push_str("========\n\n");

    output.push_str(&format!("Image: {}\n", result.image.display()));

    output.push_str(&format!("Size:  {} bytes\n\n", result.size));

    output.push_str(&format!("Status filter: {}\n\n", status.display_name()));

    let mut total = 0usize;

    /*
     * Iterate over all models because an image may
     * contain more than one partition/filesystem.
     */
    for (model_index, model) in result.models.iter().enumerate() {
        let Some(model) = model else {
            continue;
        };

        let entries: Vec<&ForensicEntry> = model
            .entries()
            .iter()
            .filter(|entry| status.matches(entry.identity.status))
            .collect();

        if entries.is_empty() {
            continue;
        }

        output.push_str(&format!("Filesystem: {:?}\n", model.source().filesystem()));

        if let Some(partition) = result.partitions.get(model_index) {
            output.push_str(&format!("Partition: #{}\n", partition.number));

            output.push_str(&format!("Start sector: {}\n", partition.start_sector));
        }

        output.push('\n');

        output.push_str(&format!(
            "[ {} ]\n",
            format_status(match status {
                StatusFilter::Normal => ForensicStatus::Normal,

                StatusFilter::System => ForensicStatus::System,

                StatusFilter::Deleted => ForensicStatus::Deleted,

                StatusFilter::Carved => ForensicStatus::Carved,

                StatusFilter::Inconsistent => ForensicStatus::Inconsistent,

                StatusFilter::Unknown => ForensicStatus::Unknown,
            })
        ));

        for entry in entries {
            total += 1;

            format_forensic_entry_line(&mut output, entry, entry_color(entry), "  ");
        }

        output.push('\n');
    }

    if total == 0 {
        output.push_str(&format!(
            "No forensic objects found with status: {}\n",
            status.display_name()
        ));
    }

    output.push_str(&format!("\nObjects found: {}\n", total));

    output
}

/*
 * ---------------------------------------------------------
 * RECOVERY COMMAND
 * ---------------------------------------------------------
 *
 * The CLI only coordinates the operation.
 *
 * Recovery logic remains in the application layer,
 * while the physical engine remains in the core layer.
 * ---------------------------------------------------------
 */

fn recover_command(command: RecoverCommand) -> Result<()> {
    match command {
        RecoverCommand::Deleted {
            image,
            output,
            object,
        } => {
            recover_scope_command(image, output, object, RecoveryFilter::Deleted)?;
        }

        RecoverCommand::Normal {
            image,
            output,
            object,
        } => {
            recover_scope_command(image, output, object, RecoveryFilter::Normal)?;
        }

        RecoverCommand::All {
            image,
            output,
            object,
        } => {
            recover_all_command(image, output, object)?;
        }
    }

    Ok(())
}

fn recover_scope_command(
    image: PathBuf,
    output: PathBuf,
    requested_objects: Vec<u64>,
    filter: RecoveryFilter,
) -> Result<()> {
    let ticket = next_recovery_ticket()?;

    std::fs::create_dir_all(&output)?;

    let working_dir = output.join(format!(".working-{}", ticket));

    println!("Forensis");
    println!("========");
    println!();

    println!("Recovery: {} objects", filter_scope_name(filter));
    println!("Ticket: {}", ticket);

    println!("Image: {}", image.display());
    println!("Output: {}", output.display());
    println!("Working directory: {}", working_dir.display());

    println!();

    let reporter = CliProgressReporter;

    let inspection = inspect_image_with_progress(&image, &reporter)?;

    let object_ids = if requested_objects.is_empty() {
        let candidates = collect_recoverable_candidates(&inspection, filter);

        if candidates.is_empty() {
            println!(
                "No recoverable {} objects found.",
                filter_scope_name(filter).to_lowercase()
            );

            return Ok(());
        }

        println!(
            "Recoverable {} objects:",
            filter_scope_name(filter).to_lowercase()
        );

        println!();

        let item_color = match filter {
            RecoveryFilter::Deleted => COLOR_RED,
            _ => COLOR_LIGHT_YELLOW,
        };

        for (index, entry) in candidates.iter().enumerate() {
            println!(
                "{}[{}]{} {}{}",
                item_color,
                index + 1,
                COLOR_RESET,
                entry.identity.name,
                COLOR_RESET
            );

            println!("    Object ID: {}", entry.identity.object_id);

            println!("    Path: {}", entry.identity.path);

            println!();
        }

        print!(
            "{}Select objects to recover [1-{}] (e.g. 1,3,5), A=all, Q=cancel:{} ",
            COLOR_LIGHT_YELLOW,
            candidates.len(),
            COLOR_RESET
        );

        io::stdout().flush()?;

        let mut input = String::new();

        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim();

        if trimmed.eq_ignore_ascii_case("q") {
            println!("Recovery cancelled.");

            return Ok(());
        }

        let selected_positions = parse_recovery_selection(trimmed, candidates.len())?;

        if selected_positions.is_empty() {
            return Err(anyhow!("No objects selected."));
        }

        selected_positions
            .iter()
            .map(|position| {
                candidates
                    .get(position - 1)
                    .map(|entry| entry.identity.object_id)
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow!("Selected object no longer exists."))?
    } else {
        requested_objects
    };

    println!();

    let mut recovered = 0usize;

    let mut failed = 0usize;

    recover_object_loop(
        &inspection,
        &object_ids,
        &working_dir,
        &mut recovered,
        &mut failed,
    )?;

    save_recovery_work(&output, &ticket, &working_dir, recovered, failed)?;

    Ok(())
}

fn recover_object_loop(
    inspection: &InspectionResult,
    object_ids: &[u64],
    working_dir: &Path,
    recovered: &mut usize,
    failed: &mut usize,
) -> Result<()> {
    let total = object_ids.len();

    for (position_index, object_id) in object_ids.iter().enumerate() {
        let entry = inspection
            .models
            .iter()
            .flatten()
            .find_map(|model| model.entry(*object_id));

        println!("==================================================");

        println!("Recovering object {}/{}:", position_index + 1, total);

        match entry {
            Some(entry) => {
                println!("Object ID: {}", entry.identity.object_id);

                println!("Name: {}", entry.identity.name);

                println!("Path: {}", entry.identity.path);
            }

            None => {
                println!("Object ID: {}", object_id);

                println!("Name: (unknown)");

                println!("Path: (unknown)");
            }
        }

        println!();

        match recover_object_from_result(inspection, *object_id, working_dir) {
            Ok(result) => {
                print_recovery_result(&result);

                if result.recovery.is_recovered() {
                    *recovered += 1;
                } else {
                    *failed += 1;
                }
            }

            Err(error) => {
                *failed += 1;

                println!("Recovery status: {}", format_error_status());

                println!("Object ID: {}", object_id);

                println!("Recovery reason: {}", error);
            }
        }

        println!("==================================================");

        println!();
    }

    Ok(())
}

fn save_recovery_work(
    output: &Path,
    ticket: &str,
    working_dir: &Path,
    recovered: usize,
    failed: usize,
) -> Result<()> {
    println!("Recovery summary");

    println!("----------------");

    println!("Selected: {}", recovered + failed);

    println!("Recovered: {}", recovered);

    println!("Failed: {}", failed);

    let final_dir = output.join(format!("forensis-recovery-cli-{}", ticket));

    if final_dir.exists() {
        return Err(anyhow!(
            "Recovery work already exists: {}",
            final_dir.display()
        ));
    }

    std::fs::rename(working_dir, &final_dir)?;

    println!();
    println!("Recovery work saved to {}", final_dir.display());

    Ok(())
}

fn filter_scope_name(filter: RecoveryFilter) -> &'static str {
    match filter {
        RecoveryFilter::Deleted => "Deleted",
        RecoveryFilter::Normal => "Normal",
        RecoveryFilter::All => "All",
    }
}

fn collect_recoverable_candidates(
    result: &InspectionResult,
    filter: RecoveryFilter,
) -> Vec<&ForensicEntry> {
    let mut candidates: Vec<&ForensicEntry> = result
        .models
        .iter()
        .flatten()
        .flat_map(|model| model.entries())
        .filter(|entry| filter.matches(entry))
        .collect();

    candidates.sort_by(|a, b| {
        a.identity
            .path
            .to_lowercase()
            .cmp(&b.identity.path.to_lowercase())
    });

    candidates
}

fn parse_recovery_selection(input: &str, total: usize) -> Result<Vec<usize>> {
    if input.eq_ignore_ascii_case("a") {
        return Ok((1..=total).collect());
    }

    if input.is_empty() {
        return Err(anyhow!("No objects selected."));
    }

    let mut selections = Vec::new();

    for item in input.split(',') {
        let position: usize = item
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid selection: {}", item.trim()))?;

        if position == 0 || position > total {
            return Err(anyhow!(
                "Selection out of range: {}. Valid range is 1-{}.",
                position,
                total
            ));
        }

        if !selections.contains(&position) {
            selections.push(position);
        }
    }

    Ok(selections)
}

fn print_recovery_result(result: &forensis_app::RecoveredFile) {
    if result.recovery.is_recovered() {
        println!("Recovery status: {}Recovered{}", COLOR_GREEN, COLOR_RESET);
    } else {
        println!(
            "Recovery status: {}Recovery failed{}",
            COLOR_RED, COLOR_RESET
        );
    }

    println!("Object ID: {}", result.entry.identity.object_id);

    println!(
        "Original status: {}{}{}",
        COLOR_RED,
        format_status(result.entry.identity.status),
        COLOR_RESET
    );

    println!(
        "Original path: {}{}{}",
        COLOR_CYAN, result.entry.identity.path, COLOR_RESET
    );

    let original_file_hash = result.original_sha256.as_deref().unwrap_or("Unavailable");

    println!(
        "Original file hash: {}{}{}",
        if result.original_sha256.is_some() {
            COLOR_LIGHT_BLUE
        } else {
            COLOR_GRAY
        },
        original_file_hash,
        COLOR_RESET
    );

    let recovered_bytes = result.recovery.data().map(|data| data.len()).unwrap_or(0);

    println!("Recovered bytes: {}", recovered_bytes);

    match &result.output_path {
        Some(path) => {
            println!(
                "Output path: {}{}{}",
                COLOR_GREEN,
                path.display(),
                COLOR_RESET
            );
        }

        None => {
            println!("Output path: -");
        }
    }

    match result.recovery.reason() {
        Some(reason) => {
            println!("Recovery reason: {}{}{}", COLOR_GRAY, reason, COLOR_RESET);
        }

        None => {
            println!("Recovery reason: -");
        }
    }

    let recovered_sha256 = result
        .recovered_sha256
        .as_deref()
        .unwrap_or("Not calculated");

    println!(
        "Recovered SHA-256: {}{}{}",
        COLOR_GREEN, recovered_sha256, COLOR_RESET
    );

    let (comparison, color) = match result.hash_comparison {
        HashComparison::Identical => ("Identical", COLOR_LIGHT_BLUE),

        HashComparison::Different => ("Different", COLOR_LIGHT_YELLOW),

        HashComparison::ReferenceUnavailable => ("Reference unavailable", COLOR_GRAY),
    };

    println!("Hash comparison: {}{}{}", color, comparison, COLOR_RESET);
}

fn format_error_status() -> &'static str {
    "FAILED"
}

fn recover_all_command(image: PathBuf, output: PathBuf, requested_objects: Vec<u64>) -> Result<()> {
    println!("Forensis");
    println!("========");
    println!();

    println!("Recovery: All available methods");

    println!("Image: {}", image.display());

    println!("Output: {}", output.display());

    println!();

    let reporter = CliProgressReporter;

    let inspection = inspect_image_with_progress(&image, &reporter)?;

    let results = if requested_objects.is_empty() {
        recover_all_from_result(&inspection, &output, &reporter)?
    } else {
        recover_objects_from_result(&inspection, &requested_objects, &output, &reporter)?
    };

    let total = results.len();

    let recovered = results
        .iter()
        .filter(|result| result.recovery.is_recovered())
        .count();

    let failed = total.saturating_sub(recovered);

    println!("==================================================");

    println!("Recovery objects processed: {}", total);

    println!("Recovered: {}", recovered);

    println!("Failed: {}", failed);

    println!("==================================================");

    Ok(())
}

/*
 * ---------------------------------------------------------
 * FORENSIC TREE COMMAND
 * ---------------------------------------------------------
 */

fn tree_command(path: PathBuf, requested_path: Option<String>) -> Result<()> {
    let result = inspect_image(&path)?;

    let model = match result.models.iter().flatten().next() {
        Some(model) => model,

        None => {
            println!("Forensis");
            println!("========");
            println!();
            println!("No forensic model available.");

            return Ok(());
        }
    };

    let tree = ForensicTree::from_model(model);

    println!("Forensis");
    println!("========");
    println!();

    println!("Image: {}", result.image.display());

    println!("Filesystem: {:?}", model.source().filesystem());

    println!();

    println!("Legend:");

    println!("  {}■{} Normal File", COLOR_BLUE, COLOR_RESET);

    println!("  {}■{} Normal Directory", COLOR_CYAN, COLOR_RESET);

    println!("  {}■{} System", COLOR_LIGHT_YELLOW, COLOR_RESET);

    println!("  {}■{} Deleted", COLOR_RED, COLOR_RESET);

    println!("  {}■{} Carved / Recovered", COLOR_MAGENTA, COLOR_RESET);

    println!("  {}■{} Inconsistent", COLOR_YELLOW, COLOR_RESET);

    println!("  {}■{} Unknown / Other", COLOR_GRAY, COLOR_RESET);

    println!();

    println!("Tree:");
    println!();

    if let Some(requested_path) = requested_path {
        format_tree_path(&tree, &requested_path);
    } else {
        format_tree_roots(&tree);
    }

    Ok(())
}

fn format_tree_roots(tree: &ForensicTree) {
    let roots = tree.roots();

    for (index, root) in roots.iter().enumerate() {
        let is_last = index + 1 == roots.len();

        format_tree_node(root, "", is_last, true);
    }
}

fn format_tree_path(tree: &ForensicTree, requested_path: &str) {
    let normalized_path = normalize_tree_path(requested_path);

    let root = tree
        .roots()
        .iter()
        .find(|node| normalize_tree_path(node.path()) == normalized_path);

    match root {
        Some(node) => {
            format_tree_node(node, "", true, true);
        }

        None => {
            if let Some(node) = find_tree_node_by_path(tree, &normalized_path) {
                format_tree_node(node, "", true, true);
            } else {
                println!("Path not found: {}", requested_path);
            }
        }
    }
}

fn find_tree_node_by_path<'a>(
    tree: &'a ForensicTree,
    requested_path: &str,
) -> Option<&'a ForensicTreeNode> {
    for root in tree.roots() {
        if let Some(node) = find_tree_node_by_path_recursive(root, requested_path) {
            return Some(node);
        }
    }

    None
}

fn find_tree_node_by_path_recursive<'a>(
    node: &'a ForensicTreeNode,
    requested_path: &str,
) -> Option<&'a ForensicTreeNode> {
    if normalize_tree_path(node.path()) == requested_path {
        return Some(node);
    }

    for child in node.children() {
        if let Some(found) = find_tree_node_by_path_recursive(child, requested_path) {
            return Some(found);
        }
    }

    None
}

fn normalize_tree_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }

    let mut normalized = path.to_string();

    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }

    if normalized.len() > 1 {
        while normalized.ends_with('/') {
            normalized.pop();
        }
    }

    normalized
}

/*
 * ---------------------------------------------------------
 * TREE FORMATTER
 * ---------------------------------------------------------
 */

fn format_tree_node(node: &ForensicTreeNode, prefix: &str, is_last: bool, is_root: bool) {
    let connector = if is_root {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    let name = if node.path() == "/" { "/" } else { node.name() };

    let color = tree_node_color(node);

    print!("{}{}{}{}{}", prefix, connector, color, name, COLOR_RESET);

    if node.is_directory() {
        print!("/");
    }

    println!("  (Object ID: {})", node.object_id());

    let child_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{}    ", prefix)
    } else {
        format!("{}│   ", prefix)
    };

    let mut children: Vec<&ForensicTreeNode> = node.children().iter().collect();

    children.sort_by(|a, b| {
        a.name()
            .to_ascii_lowercase()
            .cmp(&b.name().to_ascii_lowercase())
    });

    for (index, child) in children.iter().enumerate() {
        let child_is_last = index + 1 == children.len();

        format_tree_node(child, &child_prefix, child_is_last, false);
    }
}

fn tree_node_color(node: &ForensicTreeNode) -> &'static str {
    match node.status() {
        ForensicStatus::Deleted => COLOR_RED,

        ForensicStatus::Carved => COLOR_MAGENTA,

        ForensicStatus::Inconsistent => COLOR_YELLOW,

        ForensicStatus::System => COLOR_LIGHT_YELLOW,

        ForensicStatus::Unknown => COLOR_GRAY,

        ForensicStatus::Normal => {
            if node.is_directory() {
                COLOR_CYAN
            } else {
                COLOR_BLUE
            }
        }
    }
}

/*
 * ---------------------------------------------------------
 * ANSI TERMINAL COLORS
 * ---------------------------------------------------------
 */

const COLOR_RESET: &str = "\x1b[0m";

const COLOR_BLUE: &str = "\x1b[34m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_LIGHT_BLUE: &str = "\x1b[94m";

const COLOR_RED: &str = "\x1b[31m";

const COLOR_YELLOW: &str = "\x1b[92m";
const COLOR_LIGHT_YELLOW: &str = "\x1b[93m";

const COLOR_GREEN: &str = "\x1b[32m";

const COLOR_MAGENTA: &str = "\x1b[35m";
const COLOR_GRAY: &str = "\x1b[90m";

/*
 * ---------------------------------------------------------
 * STANDARD INSPECTION FORMATTER
 * ---------------------------------------------------------
 */

fn format_inspection(result: &InspectionResult) -> String {
    let mut output = String::new();

    output.push_str("Forensis\n");

    output.push_str("========\n\n");

    output.push_str(&format!("Image: {}\n", result.image.display()));

    output.push_str(&format!("Size:  {} bytes\n\n", result.size));

    format_color_legend(&mut output);

    if let Some(table_type) = result.partition_table {
        output.push_str(&format!("Partition Table: {:?}\n\n", table_type));

        format_partitions(&mut output, result);

        return output;
    }

    output.push_str("Partition Table: Unknown\n\n");

    if let Some(filesystem) = result.filesystems.first() {
        output.push_str(&format!("Filesystem: {:?}\n", filesystem));

        if let Some(Some(model)) = result.models.first() {
            format_investigation(&mut output, model, 2);
        }
    }

    output
}

fn format_color_legend(output: &mut String) {
    output.push_str("Legend:\n");

    output.push_str(&format!("  {}■{} Normal File\n", COLOR_BLUE, COLOR_RESET));

    output.push_str(&format!(
        "  {}■{} Normal Directory\n",
        COLOR_CYAN, COLOR_RESET
    ));

    output.push_str(&format!(
        "  {}■{} System\n",
        COLOR_LIGHT_YELLOW, COLOR_RESET
    ));

    output.push_str(&format!("  {}■{} Deleted\n", COLOR_RED, COLOR_RESET));

    output.push_str(&format!(
        "  {}■{} Carved / Recovered\n",
        COLOR_MAGENTA, COLOR_RESET
    ));

    output.push_str(&format!(
        "  {}■{} Inconsistent\n",
        COLOR_YELLOW, COLOR_RESET
    ));

    output.push_str(&format!(
        "  {}■{} Unknown / Other\n",
        COLOR_GRAY, COLOR_RESET
    ));

    output.push('\n');
}

fn format_partitions(output: &mut String, result: &InspectionResult) {
    if result.partitions.is_empty() {
        output.push_str("No partitions detected.\n");

        return;
    }

    output.push_str("Partitions:\n");

    for (index, partition) in result.partitions.iter().enumerate() {
        output.push_str(&format!("  #{}\n", partition.number));

        output.push_str(&format!("    Type: {:?}\n", partition.partition_type));

        output.push_str(&format!("    Start sector: {}\n", partition.start_sector));

        output.push_str(&format!("    Sector count: {}\n", partition.sector_count));

        if let Some(filesystem) = result.filesystems.get(index) {
            output.push_str(&format!("    Filesystem: {:?}\n", filesystem));
        }

        if let Some(Some(model)) = result.models.get(index) {
            format_investigation(output, model, 2);
        }

        output.push('\n');
    }
}

fn format_investigation(output: &mut String, model: &ForensicModel, level: usize) {
    let indent = "    ".repeat(level);

    output.push_str(&format!("\n{}Investigation:\n", indent));

    output.push_str(&format!(
        "{}  Filesystem investigated: {:?}\n",
        indent,
        model.source().filesystem()
    ));

    output.push_str(&format!(
        "{}  Records investigated: {}\n",
        indent,
        model.records_investigated()
    ));

    output.push_str(&format!(
        "{}  Entries discovered: {}\n",
        indent,
        model.len()
    ));

    let entries = model.entries();

    if !entries.is_empty() {
        format_forensic_entries(output, entries, level + 1);
    }
}

fn format_status(status: ForensicStatus) -> &'static str {
    match status {
        ForensicStatus::Normal => "NORMAL",

        ForensicStatus::System => "SYSTEM",

        ForensicStatus::Deleted => "DELETED",

        ForensicStatus::Carved => "RECOVERED",

        ForensicStatus::Inconsistent => "INCONSISTENT",

        ForensicStatus::Unknown => "UNKNOWN",
    }
}

fn format_forensic_entries(output: &mut String, entries: &[ForensicEntry], level: usize) {
    let indent = "    ".repeat(level);

    format_entry_group(output, entries, ForensicStatus::System, &indent);

    format_entry_group(output, entries, ForensicStatus::Normal, &indent);

    format_entry_group(output, entries, ForensicStatus::Deleted, &indent);

    format_entry_group(output, entries, ForensicStatus::Carved, &indent);

    format_entry_group(output, entries, ForensicStatus::Inconsistent, &indent);

    format_entry_group(output, entries, ForensicStatus::Unknown, &indent);
}

fn format_entry_group(
    output: &mut String,
    entries: &[ForensicEntry],
    status: ForensicStatus,
    indent: &str,
) {
    let group: Vec<&ForensicEntry> = entries
        .iter()
        .filter(|entry| entry.identity.status == status)
        .collect();

    if group.is_empty() {
        return;
    }

    output.push('\n');

    output.push_str(indent);

    output.push_str(status_group_color(status));

    output.push_str("[ ");

    output.push_str(format_status(status));

    output.push_str(" ]");

    output.push_str(COLOR_RESET);

    output.push('\n');

    for entry in group {
        let color = entry_color(entry);

        format_forensic_entry_line(output, entry, color, indent);
    }
}

fn status_group_color(status: ForensicStatus) -> &'static str {
    match status {
        ForensicStatus::Normal => COLOR_BLUE,

        ForensicStatus::System => COLOR_LIGHT_YELLOW,

        ForensicStatus::Deleted => COLOR_RED,

        ForensicStatus::Carved => COLOR_MAGENTA,

        ForensicStatus::Inconsistent => COLOR_YELLOW,

        ForensicStatus::Unknown => COLOR_GRAY,
    }
}

fn entry_color(entry: &ForensicEntry) -> &'static str {
    match entry.identity.status {
        ForensicStatus::Deleted => COLOR_RED,

        ForensicStatus::Carved => COLOR_MAGENTA,

        ForensicStatus::Inconsistent => COLOR_YELLOW,

        ForensicStatus::System => COLOR_LIGHT_YELLOW,

        ForensicStatus::Unknown => COLOR_GRAY,

        ForensicStatus::Normal => match entry.identity.kind {
            ForensicEntryKind::Directory => COLOR_CYAN,

            ForensicEntryKind::File => COLOR_BLUE,

            ForensicEntryKind::Symlink => COLOR_MAGENTA,

            ForensicEntryKind::Other => COLOR_GRAY,
        },
    }
}

fn format_forensic_entry_line(
    output: &mut String,
    entry: &ForensicEntry,
    color: &str,
    indent: &str,
) {
    let entry_type = match entry.identity.kind {
        ForensicEntryKind::File => "File",

        ForensicEntryKind::Directory => "Directory",

        ForensicEntryKind::Symlink => "Symlink",

        ForensicEntryKind::Other => "Other",
    };

    output.push_str(indent);

    output.push_str("  ");

    output.push_str(color);

    output.push_str(&format!("[{}]", entry_type));

    output.push_str(COLOR_RESET);

    output.push(' ');

    output.push_str(color);

    output.push_str(&entry.identity.name);

    output.push_str(COLOR_RESET);

    output.push_str("  ");

    output.push_str(&entry.identity.path);

    output.push_str(&format!("  (Object ID: {})", entry.identity.object_id));

    output.push('\n');
}

/*
 * ---------------------------------------------------------
 * DETAILED OBJECT INSPECTION
 * ---------------------------------------------------------
 */

fn format_detail(result: &InspectionResult, object_id: u64) -> String {
    for model in result.models.iter().flatten() {
        if let Some(entry) = model
            .entries()
            .iter()
            .find(|entry| entry.identity.object_id == object_id)
        {
            return format_forensic_entry_detail(entry);
        }
    }

    format!(
        "Forensis\n\
         ========\n\n\
         Object ID: {} not found.\n",
        object_id
    )
}

fn format_forensic_entry_detail(entry: &ForensicEntry) -> String {
    let color = entry_color(entry);

    let entry_type = match entry.identity.kind {
        ForensicEntryKind::File => "File",

        ForensicEntryKind::Directory => "Directory",

        ForensicEntryKind::Symlink => "Symlink",

        ForensicEntryKind::Other => "Other",
    };

    let mut output = String::new();

    output.push_str("Forensis\n");

    output.push_str("========\n\n");

    output.push_str("Object detail\n");

    output.push_str("-------------\n\n");

    output.push_str(&format!(
        "Object ID:              {}\n",
        entry.identity.object_id
    ));

    output.push_str(&format!(
        "Name:                   {}\n",
        entry.identity.name
    ));

    output.push_str(&format!(
        "Path:                   {}\n",
        entry.identity.path
    ));

    if let Some(parent_id) = entry.hierarchy.parent_id {
        output.push_str(&format!("Parent ID:              {}\n", parent_id));
    }

    output.push_str(&format!("Type:                   {}\n", entry_type));

    output.push_str("Status:                 ");

    output.push_str(color);

    output.push_str(format_status(entry.identity.status));

    output.push_str(COLOR_RESET);

    output.push('\n');

    output.push('\n');

    output.push_str(&format!(
        "Filesystem:             {:?}\n",
        entry.filesystem.filesystem
    ));

    output.push_str(&format!(
        "Filesystem object ID:   {}\n",
        entry.filesystem.filesystem_object_id
    ));

    if let Some(real_size) = entry.metadata.real_size {
        output.push_str(&format!("Real size:              {} bytes\n", real_size));
    }

    if let Some(allocated_size) = entry.metadata.allocated_size {
        output.push_str(&format!(
            "Allocated size:         {} bytes\n",
            allocated_size
        ));
    }

    if let Some(created_at) = entry.metadata.created_at {
        output.push_str(&format!(
            "Created:                {}\n",
            created_at.to_rfc3339()
        ));
    }

    if let Some(modified_at) = entry.metadata.modified_at {
        output.push_str(&format!(
            "Modified:               {}\n",
            modified_at.to_rfc3339()
        ));
    }

    if let Some(accessed_at) = entry.metadata.accessed_at {
        output.push_str(&format!(
            "Accessed:               {}\n",
            accessed_at.to_rfc3339()
        ));
    }

    if let Some(allocated) = entry.allocation.allocated {
        output.push_str(&format!("Allocated:              {}\n", allocated));
    }

    if let Some(cluster_count) = entry.allocation.cluster_count {
        output.push_str(&format!("Cluster count:          {}\n", cluster_count));
    }

    if let Some(bitmap_allocated) = entry.allocation.bitmap_allocated {
        output.push_str(&format!("Bitmap allocated:       {}\n", bitmap_allocated));
    }

    if !entry.physical_location.regions.is_empty() {
        output.push_str("Physical allocation\n");

        for region in &entry.physical_location.regions {
            if let (Some(cluster_start), Some(cluster_end)) =
                (region.cluster_start, region.cluster_end)
            {
                output.push_str(&format!(
                    "    Cluster LCN:       {} - {}\n",
                    cluster_start, cluster_end
                ));
            }

            if let Some(cluster_count) = region.cluster_count() {
                output.push_str(&format!("    Clusters:          {}\n", cluster_count));
            }

            output.push_str("    Physical region:\n");

            if let (Some(sector_start), Some(sector_end)) = (region.sector_start, region.sector_end)
            {
                output.push_str(&format!(
                    "        Sector:        {} - {}\n",
                    sector_start, sector_end
                ));
            }

            if let Some(offset) = region.offset {
                output.push_str(&format!("        Offset:        {}\n", offset));
            }
        }
    }

    output
}

/*
 * ---------------------------------------------------------
 * TESTS
 * ---------------------------------------------------------
 */

#[cfg(test)]
mod tests {
    use super::*;

    use forensis_app::{
        ForensicAllocation, ForensicFilesystem, ForensicHierarchy, ForensicIdentity,
        ForensicMetadata, ForensicObject, ForensicPhysicalLocation, ForensicSource, Partition,
        PartitionTableType, PartitionType,
    };

    #[test]
    fn test_status_filter_matches() {
        assert!(StatusFilter::Normal.matches(ForensicStatus::Normal));

        assert!(StatusFilter::System.matches(ForensicStatus::System));

        assert!(StatusFilter::Deleted.matches(ForensicStatus::Deleted));

        assert!(!StatusFilter::Deleted.matches(ForensicStatus::Normal));

        assert!(!StatusFilter::System.matches(ForensicStatus::Deleted));
    }

    #[test]
    fn test_status_filter_display_name() {
        assert_eq!(StatusFilter::Normal.display_name(), "Normal");

        assert_eq!(StatusFilter::System.display_name(), "System");

        assert_eq!(StatusFilter::Deleted.display_name(), "Deleted");
    }

    #[test]
    fn test_format_status() {
        assert_eq!(format_status(ForensicStatus::Normal), "NORMAL");

        assert_eq!(format_status(ForensicStatus::System), "SYSTEM");

        assert_eq!(format_status(ForensicStatus::Deleted), "DELETED");

        assert_eq!(format_status(ForensicStatus::Carved), "RECOVERED");

        assert_eq!(format_status(ForensicStatus::Inconsistent), "INCONSISTENT");

        assert_eq!(format_status(ForensicStatus::Unknown), "UNKNOWN");
    }

    #[test]
    fn test_normalize_tree_path() {
        assert_eq!(normalize_tree_path(""), "/");

        assert_eq!(normalize_tree_path("/"), "/");

        assert_eq!(normalize_tree_path("testes"), "/testes");

        assert_eq!(normalize_tree_path("/testes/"), "/testes");
    }

    #[test]
    fn test_parse_recovery_selection() {
        assert_eq!(parse_recovery_selection("1,3,5", 5).unwrap(), vec![1, 3, 5]);
    }

    #[test]
    fn test_parse_recovery_selection_removes_duplicates() {
        assert_eq!(
            parse_recovery_selection("1,3,1,5,3", 5).unwrap(),
            vec![1, 3, 5]
        );
    }

    #[test]
    fn test_parse_recovery_selection_all() {
        assert_eq!(parse_recovery_selection("A", 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_parse_recovery_selection_rejects_zero() {
        assert!(parse_recovery_selection("0", 4).is_err());
    }

    #[test]
    fn test_parse_recovery_selection_rejects_out_of_range() {
        assert!(parse_recovery_selection("5", 4).is_err());
    }

    #[test]
    fn test_parse_recovery_selection_rejects_invalid_value() {
        assert!(parse_recovery_selection("1,x", 4).is_err());
    }

    #[test]
    fn test_collect_deleted_entries() {
        let normal_entry = ForensicEntry::new(
            ForensicIdentity::new(
                "normal.txt",
                "/normal.txt",
                ForensicEntryKind::File,
                ForensicStatus::Normal,
                64,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(20), Some(20)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 64),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        let deleted_entry = ForensicEntry::new(
            ForensicIdentity::new(
                "deleted.txt",
                "/deleted.txt",
                ForensicEntryKind::File,
                ForensicStatus::Deleted,
                88,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(100), Some(100)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 88),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        let source = ForensicSource::new(Some("disk.img".to_string()), ForensicFilesystem::Ntfs);

        let model = ForensicModel::new(source, 89, vec![normal_entry, deleted_entry]);

        let result = InspectionResult {
            image: PathBuf::from("disk.img"),

            size: 1024,

            partition_table: None,

            partitions: Vec::new(),

            filesystems: vec![forensis_app::FileSystemType::Ntfs],

            models: vec![Some(model)],

            trees: Vec::new(),
        };

        let entries = collect_recoverable_candidates(&result, RecoveryFilter::Deleted);

        assert_eq!(entries.len(), 1);

        assert_eq!(entries[0].identity.object_id, 88);

        assert_eq!(entries[0].identity.status, ForensicStatus::Deleted);
    }

    #[test]
    fn test_format_inspection() {
        let forensic_entry = ForensicEntry::new(
            ForensicIdentity::new(
                "documento.txt",
                "documento.txt",
                ForensicEntryKind::File,
                ForensicStatus::Normal,
                64,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(20), Some(20)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 64),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        let source = ForensicSource::new(Some("disk.img".to_string()), ForensicFilesystem::Ntfs);

        let model = ForensicModel::new(source, 70, vec![forensic_entry]);

        let result = InspectionResult {
            image: PathBuf::from("disk.img"),

            size: 1024,

            partition_table: Some(PartitionTableType::Mbr),

            partitions: vec![Partition {
                number: 1,

                start_sector: 2048,

                sector_count: 10000,

                partition_type: PartitionType::Ntfs,
            }],

            filesystems: vec![forensis_app::FileSystemType::Ntfs],

            models: vec![Some(model)],

            trees: Vec::new(),
        };

        let output = format_inspection(&result);

        assert!(output.contains("Forensis"));

        assert!(output.contains("disk.img"));

        assert!(output.contains("1024 bytes"));

        assert!(output.contains("Partition Table: Mbr"));

        assert!(output.contains("#1"));

        assert!(output.contains("Start sector: 2048"));

        assert!(output.contains("Sector count: 10000"));

        assert!(output.contains("Ntfs"));

        assert!(output.contains("documento.txt"));

        assert!(output.contains("Records investigated: 70"));

        assert!(output.contains("Entries discovered: 1"));

        assert!(output.contains("[ NORMAL ]"));

        assert!(output.contains("(Object ID: 64)"));

        assert!(output.contains("Normal File"));

        assert!(output.contains("Normal Directory"));
    }

    #[test]
    fn test_format_detail_finds_object() {
        let forensic_entry = ForensicEntry::new(
            ForensicIdentity::new(
                "documento.txt",
                "/documento.txt",
                ForensicEntryKind::File,
                ForensicStatus::Normal,
                64,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(20), Some(20)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 64),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        let source = ForensicSource::new(Some("disk.img".to_string()), ForensicFilesystem::Ntfs);

        let model = ForensicModel::new(source, 70, vec![forensic_entry]);

        let result = InspectionResult {
            image: PathBuf::from("disk.img"),

            size: 1024,

            partition_table: None,

            partitions: Vec::new(),

            filesystems: vec![forensis_app::FileSystemType::Ntfs],

            models: vec![Some(model)],

            trees: Vec::new(),
        };

        let output = format_detail(&result, 64);

        assert!(output.contains("Object detail"));

        assert!(output.contains("Object ID:              64"));

        assert!(output.contains("Name:                   documento.txt"));

        assert!(output.contains("Path:                   /documento.txt"));

        assert!(output.contains("Parent ID:              5"));

        assert!(output.contains("Type:                   File"));

        assert!(output.contains("Status:"));

        assert!(output.contains("NORMAL"));

        assert!(output.contains("Filesystem:             Ntfs"));

        assert!(output.contains("Real size:              20 bytes"));

        assert!(output.contains("Allocated size:         20 bytes"));
    }

    #[test]
    fn test_format_detail_reports_missing_object() {
        let source = ForensicSource::new(Some("disk.img".to_string()), ForensicFilesystem::Ntfs);

        let model = ForensicModel::new(source, 70, Vec::new());

        let result = InspectionResult {
            image: PathBuf::from("disk.img"),

            size: 1024,

            partition_table: None,

            partitions: Vec::new(),

            filesystems: vec![forensis_app::FileSystemType::Ntfs],

            models: vec![Some(model)],

            trees: Vec::new(),
        };

        let output = format_detail(&result, 999);

        assert!(output.contains("Object ID: 999 not found."));
    }

    #[test]
    fn test_format_status_filter() {
        let normal_entry = ForensicEntry::new(
            ForensicIdentity::new(
                "normal.txt",
                "/normal.txt",
                ForensicEntryKind::File,
                ForensicStatus::Normal,
                64,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(20), Some(20)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 64),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        let deleted_entry = ForensicEntry::new(
            ForensicIdentity::new(
                "deleted.txt",
                "/deleted.txt",
                ForensicEntryKind::File,
                ForensicStatus::Deleted,
                88,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(100), Some(100)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 88),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        let source = ForensicSource::new(Some("disk.img".to_string()), ForensicFilesystem::Ntfs);

        let model = ForensicModel::new(source, 89, vec![normal_entry, deleted_entry]);

        let result = InspectionResult {
            image: PathBuf::from("disk.img"),

            size: 1024,

            partition_table: None,

            partitions: Vec::new(),

            filesystems: vec![forensis_app::FileSystemType::Ntfs],

            models: vec![Some(model)],

            trees: Vec::new(),
        };

        let output = format_status_filter(&result, StatusFilter::Deleted);

        assert!(output.contains("Status filter: Deleted"));

        assert!(output.contains("deleted.txt"));

        assert!(!output.contains("normal.txt"));

        assert!(output.contains("Objects found: 1"));
    }
}

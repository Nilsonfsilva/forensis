use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};

use forensis_app::recovery::HashComparison;

use forensis_app::{
    discover_sources, inspect_image, next_recovery_ticket, recover_object, EvidenceSource,
    ForensicEntry, ForensicEntryKind, ForensicModel, ForensicStatus, InspectionResult,
    RecoveredFile,
};

struct NavigationState {
    current_parent: u64,
    selected: usize,
    history: Vec<u64>,
}

impl NavigationState {
    fn new(model: &ForensicModel) -> Self {
        let root = model
            .entries()
            .iter()
            .find(|entry| {
                entry.is_directory() && entry.hierarchy.parent_id == Some(entry.identity.object_id)
            })
            .map(|entry| entry.identity.object_id)
            .unwrap_or(5);

        Self {
            current_parent: root,
            selected: 0,
            history: Vec::new(),
        }
    }

    fn visible_entries<'a>(&self, model: &'a ForensicModel) -> Vec<&'a ForensicEntry> {
        let mut entries = model
            .entries()
            .iter()
            .filter(|entry| entry.hierarchy.parent_id == Some(self.current_parent))
            .collect::<Vec<_>>();

        entries.sort_by_key(|entry| (!entry.is_directory(), entry.identity.name.to_lowercase()));

        entries
    }

    fn selected_entry<'a>(&self, model: &'a ForensicModel) -> Option<&'a ForensicEntry> {
        let entries = self.visible_entries(model);
        entries.get(self.selected).copied()
    }

    fn move_up(&mut self, model: &ForensicModel) {
        let count = self.visible_entries(model).len();

        if count == 0 {
            self.selected = 0;
            return;
        }

        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn move_down(&mut self, model: &ForensicModel) {
        let count = self.visible_entries(model).len();

        if count == 0 {
            self.selected = 0;
            return;
        }

        if self.selected + 1 < count {
            self.selected += 1;
        }
    }

    fn enter(&mut self, model: &ForensicModel) {
        let entry = match self.selected_entry(model) {
            Some(entry) => entry,
            None => return,
        };

        if !entry.is_directory() {
            return;
        }

        self.history.push(self.current_parent);
        self.current_parent = entry.identity.object_id;
        self.selected = 0;
    }

    fn back(&mut self) {
        if let Some(parent) = self.history.pop() {
            self.current_parent = parent;
            self.selected = 0;
        }
    }
}

struct SourceState {
    sources: Vec<EvidenceSource>,
    selected: usize,
}

impl SourceState {
    fn new(sources: Vec<EvidenceSource>) -> Self {
        Self {
            sources,
            selected: 0,
        }
    }

    fn total_items(&self) -> usize {
        self.sources.len() + 1
    }

    fn selected_is_browse(&self) -> bool {
        self.selected == 0
    }

    fn selected_source(&self) -> Option<&EvidenceSource> {
        if self.selected == 0 {
            return None;
        }

        self.sources.get(self.selected - 1)
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn move_down(&mut self) {
        let count = self.total_items();

        if count == 0 {
            self.selected = 0;
            return;
        }

        if self.selected + 1 < count {
            self.selected += 1;
        }
    }
}

#[derive(Debug, Clone)]
struct BrowseEntry {
    path: PathBuf,
    is_directory: bool,
}

struct BrowseState {
    current_path: PathBuf,
    entries: Vec<BrowseEntry>,
    selected: usize,
    history: Vec<PathBuf>,
}

impl BrowseState {
    fn new() -> Result<Self> {
        let current_path = env::current_dir()?;

        let mut state = Self {
            current_path,
            entries: Vec::new(),
            selected: 0,
            history: Vec::new(),
        };

        state.reload()?;

        Ok(state)
    }

    fn reload(&mut self) -> Result<()> {
        self.entries.clear();
        self.selected = 0;

        for entry in fs::read_dir(&self.current_path)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let path = entry.path();

            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if metadata.is_dir() || metadata.is_file() {
                self.entries.push(BrowseEntry {
                    path,
                    is_directory: metadata.is_dir(),
                });
            }
        }

        self.entries.sort_by(|a, b| {
            (
                !a.is_directory,
                a.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase(),
            )
                .cmp(&(
                    !b.is_directory,
                    b.path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase(),
                ))
        });

        Ok(())
    }

    fn selected_entry(&self) -> Option<&BrowseEntry> {
        self.entries.get(self.selected)
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.entries.len() {
            self.selected += 1;
        }
    }

    fn enter_directory(&mut self) -> Result<()> {
        let entry = match self.selected_entry() {
            Some(entry) => entry.clone(),
            None => return Ok(()),
        };

        if !entry.is_directory {
            return Ok(());
        }

        self.history.push(self.current_path.clone());
        self.current_path = entry.path;
        self.reload()?;

        Ok(())
    }

    fn back(&mut self) -> Result<()> {
        if let Some(previous) = self.history.pop() {
            self.current_path = previous;
            self.reload()?;
        }

        Ok(())
    }
}

enum SourceMode {
    Selecting,
    Browsing,
    Inspecting,
    Recovery,
    RecoveryDetails,
    RecoverySave,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryItemStatus {
    Pending,
    Recovered,
    Failed,
}

struct RecoveryItem {
    entry: ForensicEntry,
    status: RecoveryItemStatus,
    result_index: Option<usize>,
}

struct RecoveryState {
    ticket: String,
    work_name: String,
    scope_path: String,
    candidates: Vec<RecoveryItem>,
    selected_ids: HashSet<u64>,
    results: Vec<RecoveredFile>,
    selected: usize,
    output_dir: Option<PathBuf>,
}

impl RecoveryState {
    fn new(ticket: String, scope_path: String, entries: Vec<ForensicEntry>) -> Self {
        Self {
            ticket,
            work_name: String::new(),
            scope_path,
            candidates: entries
                .into_iter()
                .map(|entry| RecoveryItem {
                    entry,
                    status: RecoveryItemStatus::Pending,
                    result_index: None,
                })
                .collect(),
            selected_ids: HashSet::new(),
            results: Vec::new(),
            selected: 0,
            output_dir: None,
        }
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.candidates.len() {
            self.selected += 1;
        }
    }

    fn selected_item(&self) -> Option<&RecoveryItem> {
        self.candidates.get(self.selected)
    }

    fn toggle_selected(&mut self) {
        let object_id = match self.selected_item() {
            Some(item) => item.entry.identity.object_id,
            None => return,
        };

        if !self.selected_ids.remove(&object_id) {
            self.selected_ids.insert(object_id);
        }
    }

    fn select_all(&mut self) {
        self.selected_ids = self
            .candidates
            .iter()
            .map(|item| item.entry.identity.object_id)
            .collect();
    }

    fn selected_count(&self) -> usize {
        self.selected_ids.len()
    }

    fn status_rank(status: RecoveryItemStatus) -> u8 {
        match status {
            RecoveryItemStatus::Recovered => 0,
            RecoveryItemStatus::Failed => 1,
            RecoveryItemStatus::Pending => 2,
        }
    }

    fn sort_results(&mut self) {
        self.candidates.sort_by(|a, b| {
            Self::status_rank(a.status)
                .cmp(&Self::status_rank(b.status))
                .then_with(|| {
                    a.entry
                        .identity
                        .name
                        .to_lowercase()
                        .cmp(&b.entry.identity.name.to_lowercase())
                })
        });

        if self.candidates.is_empty() {
            self.selected = 0;
        } else {
            self.selected = self.selected.min(self.candidates.len() - 1);
        }
    }
}

struct AppState {
    source_state: SourceState,
    source_mode: SourceMode,
    focus: Focus,
    browser: Option<BrowseState>,

    result: Option<InspectionResult>,
    navigation: Option<NavigationState>,

    recovery: Option<RecoveryState>,

    status: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Sources,
    Filesystem,
}

impl AppState {
    fn new(sources: Vec<EvidenceSource>) -> Self {
        Self {
            source_state: SourceState::new(sources),
            source_mode: SourceMode::Selecting,
            focus: Focus::Sources,
            browser: None,
            result: None,
            navigation: None,
            recovery: None,
            status: "No evidence source selected.".to_string(),
        }
    }

    fn load_result(&mut self, result: InspectionResult) {
        self.navigation = result
            .models
            .iter()
            .find_map(|model| model.as_ref())
            .map(NavigationState::new);

        self.status = filesystem_status(&result);

        self.result = Some(result);
        self.source_mode = SourceMode::Inspecting;
        self.focus = Focus::Filesystem;
        self.browser = None;
        self.recovery = None;
    }

    fn clear_inspection(&mut self) {
        self.result = None;
        self.navigation = None;
        self.recovery = None;
    }
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();

    if let Some(image_path) = args.get(1) {
        let path = PathBuf::from(image_path);

        let result = inspect_image(&path)?;

        let mut app = AppState::new(Vec::new());
        app.load_result(result);

        run_tui(app)?;
    } else {
        let sources = discover_sources(Path::new("/dev"))?;

        let app = AppState::new(sources);

        run_tui(app)?;
    }

    Ok(())
}

fn run_tui(mut app: AppState) -> Result<()> {
    enable_raw_mode()?;

    let mut stdout = io::stdout();

    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);

    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;

    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    terminal.show_cursor()?;

    result
}

fn run_app<B>(terminal: &mut Terminal<B>, app: &mut AppState) -> Result<()>
where
    B: ratatui::backend::Backend,
{
    loop {
        terminal.draw(|frame| {
            draw_ui(frame, app);
        })?;

        if !event::poll(std::time::Duration::from_millis(250))? {
            continue;
        }

        let event = event::read()?;

        let key = match event {
            Event::Key(key) => key,
            _ => continue,
        };

        if key.kind != KeyEventKind::Press {
            continue;
        }

        if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q') {
            break;
        }

        if key.code == KeyCode::Esc {
            match app.source_mode {
                SourceMode::RecoveryDetails => {
                    app.source_mode = SourceMode::Recovery;
                    app.status = "Returned to recovery selection.".to_string();
                    continue;
                }

                SourceMode::RecoverySave => {
                    app.source_mode = SourceMode::Recovery;
                    app.status = "Save operation cancelled.".to_string();
                    continue;
                }

                SourceMode::Recovery => {
                    app.source_mode = SourceMode::Inspecting;
                    app.focus = Focus::Filesystem;
                    app.recovery = None;
                    app.status = "Returned to investigation.".to_string();
                    continue;
                }

                SourceMode::Selecting | SourceMode::Browsing | SourceMode::Inspecting => {
                    break;
                }
            }
        }

        match app.source_mode {
            SourceMode::Selecting => {
                handle_source_selection(app, key.code)?;
            }

            SourceMode::Browsing => {
                handle_browser(app, key.code)?;
            }

            SourceMode::Inspecting => {
                handle_inspection(app, key.code)?;
            }

            SourceMode::Recovery => {
                handle_recovery_view(app, key.code)?;
            }

            SourceMode::RecoveryDetails => {
                handle_recovery_details(app, key.code)?;
            }

            SourceMode::RecoverySave => {
                handle_recovery_save(app, key.code)?;
            }
        }
    }

    Ok(())
}

fn handle_source_selection(app: &mut AppState, key: KeyCode) -> Result<()> {
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            app.source_state.move_up();
        }

        KeyCode::Down | KeyCode::Char('j') => {
            app.source_state.move_down();
        }

        KeyCode::Enter | KeyCode::Right => {
            if app.source_state.selected_is_browse() {
                let browser = BrowseState::new()?;

                app.browser = Some(browser);
                app.source_mode = SourceMode::Browsing;
                app.status = "Browse mode. Select an evidence image.".to_string();

                return Ok(());
            }

            let path = match app.source_state.selected_source() {
                Some(source) => source.path().to_path_buf(),
                None => return Ok(()),
            };

            let result = inspect_image(&path)?;

            app.load_result(result);
        }

        KeyCode::Char('d') | KeyCode::Char('D') => {
            app.clear_inspection();
            app.source_mode = SourceMode::Selecting;
            app.focus = Focus::Sources;
            app.status = "Select an evidence source.".to_string();
        }

        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.clear_inspection();
            app.source_mode = SourceMode::Selecting;
            app.focus = Focus::Sources;
            app.status = "Select an evidence source.".to_string();
        }

        _ => {}
    }

    Ok(())
}

fn handle_browser(app: &mut AppState, key: KeyCode) -> Result<()> {
    let browser = match app.browser.as_mut() {
        Some(browser) => browser,
        None => return Ok(()),
    };

    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            browser.move_up();
        }

        KeyCode::Down | KeyCode::Char('j') => {
            browser.move_down();
        }

        KeyCode::Left | KeyCode::Backspace => {
            browser.back()?;
        }

        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.browser = None;
            app.source_mode = SourceMode::Selecting;
            app.focus = Focus::Sources;
            app.status = "Select an evidence source.".to_string();
        }

        KeyCode::Char('d') | KeyCode::Char('D') => {
            app.browser = None;
            app.source_mode = SourceMode::Selecting;
            app.focus = Focus::Sources;
            app.status = "Select an evidence source.".to_string();
        }

        KeyCode::Enter | KeyCode::Right => {
            let entry = match browser.selected_entry() {
                Some(entry) => entry.clone(),
                None => return Ok(()),
            };

            if entry.is_directory {
                browser.enter_directory()?;
            } else {
                let path = entry.path;

                let result = inspect_image(&path)?;

                app.load_result(result);
            }
        }

        _ => {}
    }

    Ok(())
}

fn handle_inspection(app: &mut AppState, key: KeyCode) -> Result<()> {
    match key {
        KeyCode::Tab => {
            app.focus = match app.focus {
                Focus::Sources => Focus::Filesystem,
                Focus::Filesystem => Focus::Sources,
            };

            return Ok(());
        }

        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.clear_inspection();
            app.source_mode = SourceMode::Selecting;
            app.focus = Focus::Sources;
            app.status = "Select an evidence source.".to_string();

            return Ok(());
        }

        KeyCode::Char('d') | KeyCode::Char('D') => {
            app.clear_inspection();
            app.source_mode = SourceMode::Selecting;
            app.focus = Focus::Sources;
            app.status = "Select an evidence source.".to_string();

            return Ok(());
        }

        KeyCode::Char('r') | KeyCode::Char('R') => {
            start_recovery(app);
            return Ok(());
        }

        _ => {}
    }

    match app.focus {
        Focus::Sources => {
            handle_source_selection(app, key)?;
        }

        Focus::Filesystem => {
            handle_filesystem_inspection(app, key)?;
        }
    }

    Ok(())
}

fn start_recovery(app: &mut AppState) {
    let ticket = match next_recovery_ticket() {
        Ok(ticket) => ticket,
        Err(error) => {
            app.status = format!("Unable to generate recovery ticket: {}", error);
            return;
        }
    };

    let (_, scope_path, candidates) = {
        let result = match &app.result {
            Some(result) => result,
            None => {
                app.status = "No investigation loaded.".to_string();
                return;
            }
        };

        let model = match result.models.iter().find_map(|model| model.as_ref()) {
            Some(model) => model,
            None => {
                app.status = "No forensic model available.".to_string();
                return;
            }
        };

        let navigation = match &app.navigation {
            Some(navigation) => navigation,
            None => {
                app.status = "No filesystem navigation available.".to_string();
                return;
            }
        };

        let scope_parent = navigation.current_parent;

        let scope_path = model
            .entries()
            .iter()
            .find(|entry| entry.identity.object_id == scope_parent)
            .map(|entry| entry.identity.path.clone())
            .unwrap_or_else(|| "/".to_string());

        let candidates = collect_recoverable_entries(model, scope_parent);

        (scope_parent, scope_path, candidates)
    };

    let candidate_count = candidates.len();

    app.recovery = Some(RecoveryState::new(ticket, scope_path.clone(), candidates));

    app.source_mode = SourceMode::Recovery;
    app.focus = Focus::Filesystem;

    app.status = if candidate_count == 0 {
        format!("No deleted files found recursively under {}.", scope_path)
    } else {
        format!(
            "{} deleted file(s) found recursively under {}.",
            candidate_count, scope_path
        )
    };
}

fn collect_recoverable_entries(model: &ForensicModel, root_id: u64) -> Vec<ForensicEntry> {
    let entries = model.entries();

    let mut children = std::collections::HashMap::<u64, Vec<&ForensicEntry>>::new();

    for entry in entries {
        if let Some(parent_id) = entry.hierarchy.parent_id {
            children.entry(parent_id).or_default().push(entry);
        }
    }

    let mut result = Vec::new();
    let mut stack = vec![root_id];

    /*
     * A forensic hierarchy must be traversed defensively.
     *
     * Filesystem metadata can be inconsistent or corrupted.
     * Without a visited set, a directory cycle such as
     * A -> B -> C -> A would cause an infinite traversal.
     */
    let mut visited = HashSet::new();

    while let Some(parent_id) = stack.pop() {
        if !visited.insert(parent_id) {
            continue;
        }

        let children_of_parent = match children.get(&parent_id) {
            Some(children) => children,
            None => continue,
        };

        for entry in children_of_parent {
            if entry.is_directory() {
                stack.push(entry.identity.object_id);
                continue;
            }

            if entry.identity.status == ForensicStatus::Deleted {
                result.push((*entry).clone());
            }
        }
    }

    result.sort_by(|a, b| {
        a.identity
            .path
            .to_lowercase()
            .cmp(&b.identity.path.to_lowercase())
    });

    result
}

fn handle_recovery_view(app: &mut AppState, key: KeyCode) -> Result<()> {
    let recovery = match app.recovery.as_mut() {
        Some(recovery) => recovery,
        None => {
            app.source_mode = SourceMode::Inspecting;
            return Ok(());
        }
    };

    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            recovery.move_up();
        }

        KeyCode::Down | KeyCode::Char('j') => {
            recovery.move_down();
        }

        KeyCode::Char(' ') => {
            recovery.toggle_selected();

            let count = recovery.selected_count();

            app.status = format!("{} file(s) selected.", count);
        }

        KeyCode::Char('a') | KeyCode::Char('A') => {
            recovery.select_all();

            let count = recovery.selected_count();

            app.status = format!("All {} file(s) selected.", count);
        }

        KeyCode::Enter => {
            execute_selected_recovery(app)?;
        }

        KeyCode::Char('d') | KeyCode::Char('D') => {
            let processed = recovery
                .selected_item()
                .map(|item| item.status != RecoveryItemStatus::Pending)
                .unwrap_or(false);

            if processed {
                app.source_mode = SourceMode::RecoveryDetails;
                app.status = "Recovery details.".to_string();
            } else {
                app.status = "Selected file has not been processed.".to_string();
            }
        }

        KeyCode::Char('w') | KeyCode::Char('W') => {
            app.source_mode = SourceMode::RecoverySave;

            if let Some(recovery) = app.recovery.as_mut() {
                recovery.work_name.clear();
            }

            app.status = "Enter work name and press Enter to save.".to_string();
        }

        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.source_mode = SourceMode::Inspecting;
            app.focus = Focus::Filesystem;
            app.recovery = None;
            app.status = "Returned to investigation.".to_string();
        }

        _ => {}
    }

    Ok(())
}

fn execute_selected_recovery(app: &mut AppState) -> Result<()> {
    let object_ids = {
        let recovery = match &app.recovery {
            Some(recovery) => recovery,
            None => return Ok(()),
        };

        if recovery.selected_ids.is_empty() {
            app.status = "No files selected for recovery.".to_string();
            return Ok(());
        }

        recovery.selected_ids.iter().copied().collect::<Vec<_>>()
    };

    let image_path = match &app.result {
        Some(result) => result.image.clone(),
        None => {
            app.status = "No investigation loaded.".to_string();
            return Ok(());
        }
    };

    let ticket = match &app.recovery {
        Some(recovery) => recovery.ticket.clone(),
        None => return Ok(()),
    };

    let working_dir = PathBuf::from("forensis-recovery").join(format!(".working-{}", ticket));

    fs::create_dir_all(&working_dir)?;

    let mut new_results = Vec::new();

    for object_id in object_ids {
        let result = recover_object(&image_path, object_id, &working_dir);

        match result {
            Ok(file) => {
                new_results.push(file);
            }

            Err(error) => {
                let entry = {
                    let recovery = match &app.recovery {
                        Some(recovery) => recovery,
                        None => continue,
                    };

                    recovery
                        .candidates
                        .iter()
                        .find(|item| item.entry.identity.object_id == object_id)
                        .map(|item| item.entry.clone())
                };

                if let Some(entry) = entry {
                    app.status = format!("Recovery error for {}: {}", entry.identity.name, error);
                }
            }
        }
    }

    if let Some(recovery) = app.recovery.as_mut() {
        for file in new_results {
            let object_id = file.entry.identity.object_id;

            let result_index = recovery.results.len();

            let success = file.output_path.is_some();

            recovery.results.push(file);

            if let Some(item) = recovery
                .candidates
                .iter_mut()
                .find(|item| item.entry.identity.object_id == object_id)
            {
                item.status = if success {
                    RecoveryItemStatus::Recovered
                } else {
                    RecoveryItemStatus::Failed
                };

                item.result_index = Some(result_index);
            }

            recovery.selected_ids.remove(&object_id);
        }

        recovery.output_dir = Some(working_dir);
        recovery.sort_results();

        let recovered = recovery
            .candidates
            .iter()
            .filter(|item| item.status == RecoveryItemStatus::Recovered)
            .count();

        let failed = recovery
            .candidates
            .iter()
            .filter(|item| item.status == RecoveryItemStatus::Failed)
            .count();

        app.status = format!(
            "Recovery completed — {} recovered, {} failed.",
            recovered, failed
        );
    }

    Ok(())
}

fn handle_recovery_details(app: &mut AppState, key: KeyCode) -> Result<()> {
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            if let Some(recovery) = app.recovery.as_mut() {
                recovery.move_up();
            }
        }

        KeyCode::Down | KeyCode::Char('j') => {
            if let Some(recovery) = app.recovery.as_mut() {
                recovery.move_down();
            }
        }

        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.source_mode = SourceMode::Recovery;
            app.status = "Returned to recovery selection.".to_string();
        }

        _ => {}
    }

    Ok(())
}

fn handle_recovery_save(app: &mut AppState, key: KeyCode) -> Result<()> {
    match key {
        KeyCode::Backspace => {
            if let Some(recovery) = app.recovery.as_mut() {
                recovery.work_name.pop();
            }
        }

        KeyCode::Enter => {
            save_recovery_work(app)?;
        }

        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.source_mode = SourceMode::Recovery;
            app.status = "Save operation cancelled.".to_string();
        }

        KeyCode::Char(c) if !c.is_control() => {
            if let Some(recovery) = app.recovery.as_mut() {
                recovery.work_name.push(c);
            }
        }

        _ => {}
    }

    Ok(())
}

fn save_recovery_work(app: &mut AppState) -> Result<()> {
    let (ticket, working_dir) = {
        let recovery = match &app.recovery {
            Some(recovery) => recovery,
            None => return Ok(()),
        };

        let working_dir = recovery.output_dir.clone().unwrap_or_else(|| {
            PathBuf::from("forensis-recovery").join(format!(".working-{}", recovery.ticket))
        });

        (recovery.ticket.clone(), working_dir)
    };

    fs::create_dir_all(&working_dir)?;

    let final_dir =
        PathBuf::from("forensis-recovery").join(format!("forensis-recovery-tui-{}", ticket));

    if final_dir.exists() {
        app.status = format!("Recovery work already exists: {}", final_dir.display());
        return Ok(());
    }

    fs::rename(&working_dir, &final_dir)?;

    if let Some(recovery) = app.recovery.as_mut() {
        recovery.output_dir = Some(final_dir.clone());
    }

    app.source_mode = SourceMode::Recovery;
    app.status = format!("Recovery work saved to {}.", final_dir.display());

    Ok(())
}

fn handle_filesystem_inspection(app: &mut AppState, key: KeyCode) -> Result<()> {
    let result = match &app.result {
        Some(result) => result,
        None => return Ok(()),
    };

    let model = match result.models.iter().find_map(|model| model.as_ref()) {
        Some(model) => model,
        None => return Ok(()),
    };

    let navigation = match app.navigation.as_mut() {
        Some(navigation) => navigation,
        None => return Ok(()),
    };

    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            navigation.move_up(model);
        }

        KeyCode::Down | KeyCode::Char('j') => {
            navigation.move_down(model);
        }

        KeyCode::Enter | KeyCode::Right => {
            navigation.enter(model);
        }

        KeyCode::Left | KeyCode::Backspace => {
            navigation.back();
        }

        _ => {}
    }

    Ok(())
}

fn filesystem_status(result: &InspectionResult) -> String {
    if result.filesystems.is_empty() {
        return "Filesystem: Unknown — unable to identify filesystem.".to_string();
    }

    let mut statuses = Vec::new();

    for filesystem in &result.filesystems {
        if filesystem.is_supported() {
            statuses.push(format!(
                "Filesystem: {} — Supported",
                filesystem.display_name()
            ));
        } else {
            statuses.push(format!(
                "Filesystem: {} — Filesystem not supported",
                filesystem.display_name()
            ));
        }
    }

    statuses.join(" | ")
}

fn draw_ui(frame: &mut ratatui::Frame, app: &AppState) {
    let area = frame.area();

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(frame, app, vertical[0]);

    match app.source_mode {
        SourceMode::Recovery => {
            draw_recovery_context(frame, app, vertical[1]);
            draw_recovery_panels(frame, app, vertical[2]);
        }

        SourceMode::RecoveryDetails => {
            draw_recovery_context(frame, app, vertical[1]);
            draw_recovery_details_screen(frame, app, vertical[2]);
        }

        SourceMode::RecoverySave => {
            draw_recovery_context(frame, app, vertical[1]);
            draw_recovery_save(frame, app, vertical[2]);
        }

        SourceMode::Selecting | SourceMode::Browsing | SourceMode::Inspecting => {
            draw_source_area(frame, app, vertical[1]);
            draw_inspection_panels(frame, app, vertical[2]);
        }
    }

    draw_footer(frame, app, vertical[3]);
}

fn draw_header(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let source_text = match &app.result {
        Some(result) => result.image.display().to_string(),
        None => "None".to_string(),
    };

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "FORENSIS — Digital Forensic Investigation   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("■ Normal File ", Style::default().fg(Color::Blue)),
            Span::styled("■ Directory ", Style::default().fg(Color::Cyan)),
            Span::styled("■ System ", Style::default().fg(Color::LightYellow)),
            Span::styled("■ System/Deleted ", Style::default().fg(Color::Red)),
            Span::styled("■ Carved ", Style::default().fg(Color::Magenta)),
            Span::styled("■ Inconsistent ", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(
                "Source: ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(source_text, Style::default().fg(Color::Cyan)),
        ]),
    ])
    .style(Style::default().fg(Color::White))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Case "),
    );

    frame.render_widget(header, area);
}

fn draw_source_area(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    match app.source_mode {
        SourceMode::Selecting | SourceMode::Inspecting => {
            draw_source_selection(frame, app, body[0], body[1]);
        }

        SourceMode::Browsing => {
            draw_browser_selection(frame, app, body[0], body[1]);
        }

        SourceMode::Recovery | SourceMode::RecoveryDetails | SourceMode::RecoverySave => {}
    }
}

fn draw_source_selection(
    frame: &mut ratatui::Frame,
    app: &AppState,
    list_area: ratatui::layout::Rect,
    info_area: ratatui::layout::Rect,
) {
    let mut items = Vec::new();

    items.push(ListItem::new(Line::from(vec![Span::styled(
        "[BROWSE] Browse filesystem",
        Style::default().fg(Color::Cyan),
    )])));

    for source in &app.source_state.sources {
        let kind = format!("{:?}", source.kind());

        let text = format!("{}  [{}]", source.path().display(), kind);

        items.push(ListItem::new(Line::from(vec![Span::styled(
            text,
            Style::default().fg(Color::White),
        )])));
    }
    let focused = matches!(app.source_mode, SourceMode::Selecting) || app.focus == Focus::Sources;

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focused {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::White)
                })
                .title(format!(
                    " Evidence Sources — {} sources ",
                    app.source_state.sources.len()
                )),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➤ ");

    let mut list_state = ListState::default();

    if app.source_state.total_items() > 0 {
        list_state.select(Some(
            app.source_state
                .selected
                .min(app.source_state.total_items() - 1),
        ));
    }

    frame.render_stateful_widget(list, list_area, &mut list_state);

    let info_lines = if app.source_state.selected_is_browse() {
        vec![
            Line::from(vec![Span::styled(
                "Browse",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from("Navigate through the filesystem."),
            Line::from("Select a forensic image and press Enter."),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Status",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(app.status.clone()),
        ]
    } else {
        match app.source_state.selected_source() {
            Some(source) => vec![
                Line::from(vec![Span::styled(
                    "Selected Source",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                detail_line("Path", &source.path().display().to_string(), Color::Cyan),
                detail_line("Kind", &format!("{:?}", source.kind()), Color::Cyan),
                Line::from(""),
                Line::from("Press Enter to inspect this source."),
                Line::from(vec![Span::styled(
                    app.status.clone(),
                    Style::default().fg(Color::Gray),
                )]),
            ],

            None => vec![Line::from(vec![Span::styled(
                app.status.clone(),
                Style::default().fg(Color::Gray),
            )])],
        }
    };

    let info = Paragraph::new(info_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(if focused {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            })
            .title(" Source Information "),
    );

    frame.render_widget(info, info_area);
}

fn draw_browser_selection(
    frame: &mut ratatui::Frame,
    app: &AppState,
    list_area: ratatui::layout::Rect,
    info_area: ratatui::layout::Rect,
) {
    let browser = match &app.browser {
        Some(browser) => browser,
        None => return,
    };

    let mut items = Vec::new();

    for entry in &browser.entries {
        let name = entry
            .path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| entry.path.display().to_string());

        let (prefix, color) = if entry.is_directory {
            ("[DIR ] ", Color::Cyan)
        } else {
            ("[FILE] ", Color::Blue)
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(prefix, Style::default().fg(color)),
            Span::styled(name, Style::default().fg(color)),
        ])));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::White))
                .title(format!(" Browse — {} entries ", browser.entries.len())),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➤ ");

    let mut list_state = ListState::default();

    if !browser.entries.is_empty() {
        list_state.select(Some(browser.selected.min(browser.entries.len() - 1)));
    }

    frame.render_stateful_widget(list, list_area, &mut list_state);

    let info_lines = match browser.selected_entry() {
        Some(entry) => {
            let name = entry
                .path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| entry.path.display().to_string());

            let kind = if entry.is_directory {
                "Directory"
            } else {
                "File"
            };

            vec![
                Line::from(vec![Span::styled(
                    "Selected",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                detail_line("Name", &name, Color::White),
                detail_line("Type", kind, Color::Cyan),
                Line::from(""),
                detail_line("Path", &entry.path.display().to_string(), Color::Cyan),
                Line::from(""),
                if entry.is_directory {
                    Line::from("Press Enter to open.")
                } else {
                    Line::from("Press Enter to inspect.")
                },
                Line::from(""),
                Line::from(vec![Span::styled(
                    app.status.clone(),
                    Style::default().fg(Color::Gray),
                )]),
            ]
        }

        None => vec![Line::from(vec![Span::styled(
            "Directory is empty.",
            Style::default().fg(Color::Gray),
        )])],
    };

    let info = Paragraph::new(info_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Selection "),
    );

    frame.render_widget(info, info_area);
}

fn draw_recovery_context(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let recovery = match &app.recovery {
        Some(recovery) => recovery,
        None => return,
    };

    let output = recovery
        .output_dir
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_string());

    let lines = vec![
        Line::from(vec![Span::styled(
            "RECOVERY",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        detail_line("Ticket", &recovery.ticket, Color::White),
        detail_line("Scope", &recovery.scope_path, Color::Cyan),
        detail_line(
            "Candidates",
            &recovery.candidates.len().to_string(),
            Color::White,
        ),
        detail_line(
            "Selected",
            &recovery.selected_count().to_string(),
            Color::Yellow,
        ),
        detail_line("Output", &output, Color::Green),
        Line::from(""),
        Line::from(vec![Span::styled(
            app.status.clone(),
            Style::default().fg(Color::Yellow),
        )]),
    ];

    let widget = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title(" Recovery Workspace "),
    );

    frame.render_widget(widget, area);
}

fn draw_recovery_panels(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);

    let recovery = match &app.recovery {
        Some(recovery) => recovery,
        None => return,
    };

    let mut items = Vec::new();

    for item in &recovery.candidates {
        let object_id = item.entry.identity.object_id;
        let selected = recovery.selected_ids.contains(&object_id);

        let marker = if selected { "☑ " } else { "☐ " };

        let (status_marker, color) = match item.status {
            RecoveryItemStatus::Recovered => ("🟢 ", Color::Green),
            RecoveryItemStatus::Failed => ("🔴 ", Color::Red),
            RecoveryItemStatus::Pending => ("⚪ ", Color::White),
        };

        let text = format!(
            "{}{}{}  {}",
            marker, status_marker, item.entry.identity.name, object_id
        );

        items.push(ListItem::new(Line::from(vec![Span::styled(
            text,
            Style::default().fg(color),
        )])));
    }

    let title = format!(
        " Recovery Candidates — {} file(s) ",
        recovery.candidates.len()
    );

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(title),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➤ ");

    let mut list_state = ListState::default();

    if !recovery.candidates.is_empty() {
        list_state.select(Some(recovery.selected.min(recovery.candidates.len() - 1)));
    }

    frame.render_stateful_widget(list, body[0], &mut list_state);

    let details = match recovery.selected_item() {
        Some(item) => build_recovery_item_details(item, recovery),

        None => vec![Line::from(vec![Span::styled(
            "No recovery candidate found.",
            Style::default().fg(Color::Gray),
        )])],
    };

    let details_widget = Paragraph::new(details).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Recovery Selection "),
    );

    frame.render_widget(details_widget, body[1]);
}

fn build_recovery_item_details(
    item: &RecoveryItem,
    recovery: &RecoveryState,
) -> Vec<Line<'static>> {
    let status = match item.status {
        RecoveryItemStatus::Recovered => "Recovered",
        RecoveryItemStatus::Failed => "Recovery failed",
        RecoveryItemStatus::Pending => "Not processed",
    };

    let status_color = match item.status {
        RecoveryItemStatus::Recovered => Color::Green,
        RecoveryItemStatus::Failed => Color::Red,
        RecoveryItemStatus::Pending => Color::White,
    };

    let selected = if recovery
        .selected_ids
        .contains(&item.entry.identity.object_id)
    {
        "Yes"
    } else {
        "No"
    };

    vec![
        Line::from(vec![Span::styled(
            item.entry.identity.name.clone(),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        detail_line("Selection", selected, Color::Yellow),
        detail_line("Status", status, status_color),
        detail_line(
            "Object ID",
            &item.entry.identity.object_id.to_string(),
            Color::White,
        ),
        Line::from(""),
        detail_line("Original path", &item.entry.identity.path, Color::Cyan),
        detail_line(
            "Real size",
            &item
                .entry
                .metadata
                .real_size
                .map(|size| format!("{} bytes", size))
                .unwrap_or_else(|| "-".to_string()),
            Color::White,
        ),
        detail_line(
            "Allocated size",
            &item
                .entry
                .metadata
                .allocated_size
                .map(|size| format!("{} bytes", size))
                .unwrap_or_else(|| "-".to_string()),
            Color::White,
        ),
        Line::from(""),
        Line::from("Press D for processed recovery details."),
    ]
}

fn draw_recovery_details_screen(
    frame: &mut ratatui::Frame,
    app: &AppState,
    area: ratatui::layout::Rect,
) {
    let recovery = match &app.recovery {
        Some(recovery) => recovery,
        None => return,
    };

    let item = match recovery.selected_item() {
        Some(item) => item,
        None => return,
    };

    let result = item
        .result_index
        .and_then(|index| recovery.results.get(index));

    let lines = match result {
        Some(file) => build_processed_recovery_details(file),

        None => vec![Line::from(vec![Span::styled(
            "No recovery result available.",
            Style::default().fg(Color::Red),
        )])],
    };

    let widget = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title(" Recovery Details "),
    );

    frame.render_widget(widget, area);
}

fn build_processed_recovery_details(file: &RecoveredFile) -> Vec<Line<'static>> {
    let success = file.output_path.is_some();

    let status = if success {
        "Recovered"
    } else {
        "Recovery failed"
    };

    let status_color = if success { Color::Green } else { Color::Red };

    let recovered_size = file
        .recovery
        .data()
        .map(|data| data.len().to_string())
        .unwrap_or_else(|| "0".to_string());

    let output = file
        .output_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_string());

    let original_file_hash = file.original_sha256.as_deref().unwrap_or("Unavailable");

    let recovered_sha256 = file.recovered_sha256.as_deref().unwrap_or("Not calculated");

    let (hash_comparison, hash_comparison_color, reason) = match file.hash_comparison {
        HashComparison::Identical => (
            "Identical",
            Color::LightBlue,
            "Recovery successful; SHA-256 matches the media reference.",
        ),

        HashComparison::Different => (
            "Different",
            Color::LightYellow,
            "Recovery completed; SHA-256 differs from the media reference.",
        ),

        HashComparison::ReferenceUnavailable => {
            let recovery_reason = file
                .recovery
                .reason()
                .unwrap_or("Reference SHA-256 was unavailable.");

            ("Reference unavailable", Color::Gray, recovery_reason)
        }
    };

    vec![
        Line::from(vec![Span::styled(
            file.entry.identity.name.clone(),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        detail_line("Recovery status", status, status_color),
        detail_line(
            "Object ID",
            &file.entry.identity.object_id.to_string(),
            Color::White,
        ),
        detail_line(
            "Original status",
            &format!("{:?}", file.entry.identity.status),
            Color::Red,
        ),
        Line::from(""),
        detail_line("Original path", &file.entry.identity.path, Color::Cyan),
        detail_line(
            "Original file hash",
            original_file_hash,
            if file.original_sha256.is_some() {
                Color::LightBlue
            } else {
                Color::Gray
            },
        ),
        Line::from(""),
        detail_line("Recovered bytes", &recovered_size, Color::White),
        detail_line("Output path", &output, Color::Green),
        Line::from(""),
        detail_line("Recovery reason", reason, Color::Gray),
        Line::from(""),
        detail_line("Recovered SHA-256", recovered_sha256, Color::Green),
        detail_line("Hash comparison", hash_comparison, hash_comparison_color),
    ]
}

fn draw_recovery_save(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let recovery = match &app.recovery {
        Some(recovery) => recovery,
        None => return,
    };

    let lines = vec![
        Line::from(vec![Span::styled(
            "SAVE RECOVERY WORK",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        detail_line("Ticket", &recovery.ticket, Color::Green),
        detail_line("Scope", &recovery.scope_path, Color::Cyan),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Press Enter to save the recovery work.",
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            app.status.clone(),
            Style::default().fg(Color::Yellow),
        )]),
    ];

    let widget = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Save Recovery Work "),
    );

    frame.render_widget(widget, area);
}

fn draw_inspection_panels(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(24),
            Constraint::Percentage(46),
            Constraint::Percentage(30),
        ])
        .split(area);

    match (&app.result, &app.navigation) {
        (Some(result), Some(navigation)) => {
            let model = match result.models.iter().find_map(|model| model.as_ref()) {
                Some(model) => model,
                None => {
                    draw_empty_inspection_panels(frame, app, &body);
                    return;
                }
            };

            draw_loaded_inspection(frame, result, model, navigation, app.focus, &body);
        }

        _ => {
            draw_empty_inspection_panels(frame, app, &body);
        }
    }
}

fn draw_empty_inspection_panels(
    frame: &mut ratatui::Frame,
    app: &AppState,
    areas: &[ratatui::layout::Rect],
) {
    let evidence = Paragraph::new(vec![
        Line::from(""),
        Line::from(""),
        Line::from(vec![Span::styled(
            "EMPTY",
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(app.status.clone()),
    ])
    .alignment(ratatui::layout::Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Evidence "),
    );

    frame.render_widget(evidence, areas[0]);

    let objects = Paragraph::new(vec![
        Line::from(""),
        Line::from(""),
        Line::from(vec![Span::styled(
            "EMPTY",
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        )]),
    ])
    .alignment(ratatui::layout::Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Filesystem Objects "),
    );

    frame.render_widget(objects, areas[1]);

    let details = Paragraph::new(vec![
        Line::from(""),
        Line::from(""),
        Line::from(vec![Span::styled(
            "EMPTY",
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        )]),
    ])
    .alignment(ratatui::layout::Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Details "),
    );

    frame.render_widget(details, areas[2]);
}

fn draw_loaded_inspection(
    frame: &mut ratatui::Frame,
    result: &InspectionResult,
    model: &ForensicModel,
    navigation: &NavigationState,
    focus: Focus,
    areas: &[ratatui::layout::Rect],
) {
    let filesystem = result
        .filesystems
        .first()
        .map(|filesystem| filesystem.display_name().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let partition = result
        .partition_table
        .map(|table| format!("{:?}", table))
        .unwrap_or_else(|| "None".to_string());

    let image_info = vec![
        Line::from(vec![Span::styled(
            "Image",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            result.image.display().to_string(),
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Size",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            format!("{} bytes", result.size),
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Partition Table",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            partition,
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Filesystem",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            filesystem,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Status",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            "Supported",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
    ];

    let info = Paragraph::new(image_info).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Evidence "),
    );

    frame.render_widget(info, areas[0]);

    let visible = navigation.visible_entries(model);

    let mut list_items = Vec::new();

    for entry in &visible {
        let kind = match entry.identity.kind {
            ForensicEntryKind::File => "[FILE]",
            ForensicEntryKind::Directory => "[DIR ]",
            ForensicEntryKind::Symlink => "[LINK]",
            ForensicEntryKind::Other => "[OTHER]",
        };

        let color = entry_color(entry);

        let prefix = if entry.is_directory() { "▶ " } else { "  " };

        let text = format!("{}{} {}", prefix, kind, entry.identity.name);

        list_items.push(ListItem::new(Line::from(vec![Span::styled(
            text,
            Style::default().fg(color),
        )])));
    }

    let list = List::new(list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focus == Focus::Filesystem {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::White)
                })
                .title(format!(" Filesystem Objects — {} entries ", visible.len())),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➤ ");

    let mut list_state = ListState::default();

    if !visible.is_empty() {
        list_state.select(Some(navigation.selected.min(visible.len() - 1)));
    }

    frame.render_stateful_widget(list, areas[1], &mut list_state);

    let details = navigation.selected_entry(model);

    let details_lines = match details {
        Some(entry) => build_details(entry),

        None => vec![Line::from(vec![Span::styled(
            "No object selected.",
            Style::default().fg(Color::Gray),
        )])],
    };

    let details_widget = Paragraph::new(details_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Details "),
    );

    frame.render_widget(details_widget, areas[2]);
}

fn draw_footer(frame: &mut ratatui::Frame, app: &AppState, area: ratatui::layout::Rect) {
    let footer = match app.source_mode {
        SourceMode::Selecting => Paragraph::new(Line::from(vec![
            Span::styled(
                "↑↓ ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Navigate   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Enter ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Open   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "D ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Sources   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Esc ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Quit", Style::default().fg(Color::Gray)),
        ])),

        SourceMode::Browsing => Paragraph::new(Line::from(vec![
            Span::styled(
                "↑↓ ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Navigate   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Enter ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Open   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "← ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Back   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "B ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Back   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "D ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Sources   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Esc ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Quit", Style::default().fg(Color::Gray)),
        ])),

        SourceMode::Inspecting => match app.focus {
            Focus::Sources => Paragraph::new(Line::from(vec![
                Span::styled(
                    "Focus: Sources   ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Tab ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Filesystem   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "↑↓ ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Navigate Sources   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Enter ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Open   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "B ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Back   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "D ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Sources   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Esc ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Quit", Style::default().fg(Color::Gray)),
            ])),

            Focus::Filesystem => Paragraph::new(Line::from(vec![
                Span::styled(
                    "Focus: Filesystem   ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Tab ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Sources   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "↑↓ ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Navigate Objects   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Enter ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Open   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "← ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Back   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "R ",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Recover   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "B ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Back   ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Esc ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Quit", Style::default().fg(Color::Gray)),
            ])),
        },

        SourceMode::Recovery => Paragraph::new(Line::from(vec![
            Span::styled(
                "↑↓ ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Navigate   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "SPACE ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Select   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "A ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Select All   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "ENTER ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Recover   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "D ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Details   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "W ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Save Work   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "B ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Back   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Esc ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Back", Style::default().fg(Color::Gray)),
        ])),

        SourceMode::RecoveryDetails => Paragraph::new(Line::from(vec![
            Span::styled(
                "↑↓ ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Navigate   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "B ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Back   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Esc ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Back", Style::default().fg(Color::Gray)),
        ])),

        SourceMode::RecoverySave => Paragraph::new(Line::from(vec![
            Span::styled(
                "Type ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Work Name   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Backspace ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Delete   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Enter ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Save   ", Style::default().fg(Color::Gray)),
            Span::styled(
                "Esc ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Cancel", Style::default().fg(Color::Gray)),
        ])),
    };

    frame.render_widget(footer, area);
}

fn entry_color(entry: &ForensicEntry) -> Color {
    match entry.identity.status {
        ForensicStatus::Deleted => Color::Red,
        ForensicStatus::Carved => Color::Magenta,
        ForensicStatus::Inconsistent => Color::Yellow,
        ForensicStatus::System => Color::LightYellow,
        ForensicStatus::Unknown => Color::Gray,

        ForensicStatus::Normal => match entry.identity.kind {
            ForensicEntryKind::Directory => Color::Cyan,
            ForensicEntryKind::File => Color::Blue,
            ForensicEntryKind::Symlink => Color::Magenta,
            ForensicEntryKind::Other => Color::Gray,
        },
    }
}

fn build_details(entry: &ForensicEntry) -> Vec<Line<'static>> {
    let color = entry_color(entry);

    let kind = match entry.identity.kind {
        ForensicEntryKind::File => "File",
        ForensicEntryKind::Directory => "Directory",
        ForensicEntryKind::Symlink => "Symlink",
        ForensicEntryKind::Other => "Other",
    };

    let status = format!("{:?}", entry.identity.status);

    let parent = entry
        .hierarchy
        .parent_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".to_string());

    let real_size = entry
        .metadata
        .real_size
        .map(|size| format!("{} bytes", size))
        .unwrap_or_else(|| "-".to_string());

    let allocated_size = entry
        .metadata
        .allocated_size
        .map(|size| format!("{} bytes", size))
        .unwrap_or_else(|| "-".to_string());

    let allocated = entry
        .allocation
        .allocated
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());

    vec![
        Line::from(vec![Span::styled(
            entry.identity.name.clone(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        detail_line("Type", kind, color),
        detail_line("Status", &status, color),
        detail_line(
            "Object ID",
            &entry.identity.object_id.to_string(),
            Color::White,
        ),
        detail_line("Parent ID", &parent, Color::White),
        Line::from(""),
        detail_line("Path", &entry.identity.path, Color::White),
        Line::from(""),
        detail_line("Real size", &real_size, Color::White),
        detail_line("Allocated size", &allocated_size, Color::White),
        detail_line("Allocated", &allocated, Color::White),
        Line::from(""),
        detail_line(
            "Filesystem",
            &format!("{:?}", entry.filesystem.filesystem),
            Color::Cyan,
        ),
        detail_line(
            "Filesystem object ID",
            &entry.filesystem.filesystem_object_id.to_string(),
            Color::White,
        ),
    ]
}

fn detail_line(label: &str, value: &str, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}: ", label), Style::default().fg(Color::Gray)),
        Span::styled(value.to_string(), Style::default().fg(value_color)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    use forensis_app::{
        ForensicAllocation, ForensicFilesystem, ForensicHierarchy, ForensicIdentity,
        ForensicMetadata, ForensicObject, ForensicPhysicalLocation, ForensicSource, ForensicStatus,
    };

    #[test]
    fn normal_file_is_blue() {
        let entry = ForensicEntry::new(
            ForensicIdentity::new(
                "file.txt",
                "file.txt",
                ForensicEntryKind::File,
                ForensicStatus::Normal,
                1,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(10), Some(10)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 1),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        assert_eq!(entry_color(&entry), Color::Blue);
    }

    #[test]
    fn normal_directory_is_cyan() {
        let entry = ForensicEntry::new(
            ForensicIdentity::new(
                "documents",
                "documents",
                ForensicEntryKind::Directory,
                ForensicStatus::Normal,
                64,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(0), Some(0)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 64),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        assert_eq!(entry_color(&entry), Color::Cyan);
    }

    #[test]
    fn deleted_entry_is_red() {
        let entry = ForensicEntry::new(
            ForensicIdentity::new(
                "deleted.txt",
                "deleted.txt",
                ForensicEntryKind::File,
                ForensicStatus::Deleted,
                70,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(10), Some(10)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 70),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        assert_eq!(entry_color(&entry), Color::Red);
    }

    #[test]
    fn carved_entry_is_magenta() {
        let entry = ForensicEntry::new(
            ForensicIdentity::new(
                "recovered.bin",
                "recovered.bin",
                ForensicEntryKind::File,
                ForensicStatus::Carved,
                100,
            ),
            ForensicHierarchy::new(None),
            ForensicMetadata::new(Some(100), Some(100)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 100),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        assert_eq!(entry_color(&entry), Color::Magenta);
    }

    #[test]
    fn inconsistent_entry_is_yellow() {
        let entry = ForensicEntry::new(
            ForensicIdentity::new(
                "suspicious.bin",
                "suspicious.bin",
                ForensicEntryKind::File,
                ForensicStatus::Inconsistent,
                101,
            ),
            ForensicHierarchy::new(None),
            ForensicMetadata::new(Some(100), Some(100)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 101),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        assert_eq!(entry_color(&entry), Color::Yellow);
    }

    #[test]
    fn system_entry_is_light_yellow() {
        let entry = ForensicEntry::new(
            ForensicIdentity::new(
                "$MFT",
                "$MFT",
                ForensicEntryKind::File,
                ForensicStatus::System,
                0,
            ),
            ForensicHierarchy::new(Some(5)),
            ForensicMetadata::new(Some(72704), Some(77824)),
            ForensicObject::new(ForensicFilesystem::Ntfs, 0),
            ForensicAllocation::empty(),
            ForensicPhysicalLocation::empty(),
        );

        assert_eq!(entry_color(&entry), Color::LightYellow);
    }

    #[test]
    fn collect_recoverable_entries_handles_cycles() {
        let entries = vec![
            ForensicEntry::new(
                ForensicIdentity::new(
                    "A",
                    "/A",
                    ForensicEntryKind::Directory,
                    ForensicStatus::Normal,
                    10,
                ),
                ForensicHierarchy::new(Some(30)),
                ForensicMetadata::new(Some(0), Some(0)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 10),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "B",
                    "/A/B",
                    ForensicEntryKind::Directory,
                    ForensicStatus::Normal,
                    20,
                ),
                ForensicHierarchy::new(Some(10)),
                ForensicMetadata::new(Some(0), Some(0)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 20),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "C",
                    "/A/B/C",
                    ForensicEntryKind::Directory,
                    ForensicStatus::Normal,
                    30,
                ),
                ForensicHierarchy::new(Some(20)),
                ForensicMetadata::new(Some(0), Some(0)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 30),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
            ForensicEntry::new(
                ForensicIdentity::new(
                    "deleted.txt",
                    "/A/deleted.txt",
                    ForensicEntryKind::File,
                    ForensicStatus::Deleted,
                    40,
                ),
                ForensicHierarchy::new(Some(10)),
                ForensicMetadata::new(Some(10), Some(10)),
                ForensicObject::new(ForensicFilesystem::Ntfs, 40),
                ForensicAllocation::empty(),
                ForensicPhysicalLocation::empty(),
            ),
        ];

        let model = ForensicModel::new(
            ForensicSource::new(None, ForensicFilesystem::Ntfs),
            4,
            entries,
        );

        let result = collect_recoverable_entries(&model, 10);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].identity.object_id, 40);
    }
}

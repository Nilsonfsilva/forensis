use super::model::{ForensicEntry, ForensicEntryKind, ForensicStatus};

/// Represents one node in the filesystem-independent forensic tree.
///
/// The tree is built exclusively from the common forensic model.
/// It does not depend on NTFS, EXT4, FAT32, MFT records, inodes,
/// directory entries or any other filesystem-specific structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicTreeNode {
    /// Object identifier from the forensic model.
    pub object_id: u64,

    /// Object name.
    pub name: String,

    /// Complete forensic path.
    pub path: String,

    /// Type of forensic object.
    pub kind: ForensicEntryKind,

    /// Forensic status of the object.
    pub status: ForensicStatus,

    /// Child nodes.
    pub children: Vec<ForensicTreeNode>,
}

impl ForensicTreeNode {
    /// Creates a tree node from a forensic entry.
    fn from_entry(entry: &ForensicEntry) -> Self {
        Self {
            object_id: entry.identity.object_id,
            name: entry.identity.name.clone(),
            path: entry.identity.path.clone(),
            kind: entry.identity.kind,
            status: entry.identity.status,
            children: Vec::new(),
        }
    }

    /// Returns true when this node represents a directory.
    pub fn is_directory(&self) -> bool {
        self.kind == ForensicEntryKind::Directory
    }

    /// Returns the node's object identifier.
    pub fn object_id(&self) -> u64 {
        self.object_id
    }

    /// Returns the node's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the node's forensic path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the node's forensic status.
    pub fn status(&self) -> ForensicStatus {
        self.status
    }

    /// Returns the child nodes.
    pub fn children(&self) -> &[ForensicTreeNode] {
        &self.children
    }

    /// Finds a node by its complete forensic path.
    ///
    /// The comparison is performed against the path stored in the
    /// common forensic model. No filesystem-specific information
    /// is required.
    pub fn find_path(&self, path: &str) -> Option<&ForensicTreeNode> {
        if self.path == path {
            return Some(self);
        }

        for child in &self.children {
            if let Some(found) = child.find_path(path) {
                return Some(found);
            }
        }

        None
    }
}

/// Filesystem-independent hierarchy of forensic objects.
///
/// A ForensicTree represents the navigable hierarchy of objects
/// discovered by the filesystem parser.
///
/// Filesystem-specific metadata remains in ForensicEntry. The tree
/// only uses the common identity and hierarchy information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicTree {
    roots: Vec<ForensicTreeNode>,
}

impl ForensicTree {
    /// Builds a forensic tree from a collection of forensic entries.
    ///
    /// An entry becomes a root when:
    ///
    /// 1. it has no parent; or
    /// 2. its parent is itself; or
    /// 3. its parent was not discovered.
    ///
    /// This allows the tree to represent incomplete investigations
    /// without inventing missing filesystem objects.
    pub fn from_entries(entries: &[ForensicEntry]) -> Self {
        let mut roots = Vec::new();

        for entry in entries {
            let parent_id = entry.hierarchy.parent_id;

            let is_self_parent = parent_id == Some(entry.identity.object_id);

            let has_parent = parent_id
                .map(|parent| {
                    entries
                        .iter()
                        .any(|candidate| candidate.identity.object_id == parent)
                })
                .unwrap_or(false);

            if parent_id.is_none() || is_self_parent || !has_parent {
                roots.push(Self::build_node(entry, entries));
            }
        }

        Self { roots }
    }

    /// Builds a forensic tree directly from a model.
    pub fn from_model(model: &super::model::ForensicModel) -> Self {
        Self::from_entries(model.entries())
    }

    /// Recursively builds one node.
    fn build_node(entry: &ForensicEntry, entries: &[ForensicEntry]) -> ForensicTreeNode {
        let mut node = ForensicTreeNode::from_entry(entry);

        /*
         * Only directories can contain children.
         *
         * This is a property of the common hierarchy model,
         * not of a specific filesystem.
         */
        if entry.identity.kind == ForensicEntryKind::Directory {
            for child in entries {
                /*
                 * Prevent an object from becoming its own child.
                 */
                if child.identity.object_id == entry.identity.object_id {
                    continue;
                }

                if child.hierarchy.parent_id == Some(entry.identity.object_id) {
                    node.children.push(Self::build_node(child, entries));
                }
            }
        }

        node
    }

    /// Returns all root nodes.
    pub fn roots(&self) -> &[ForensicTreeNode] {
        &self.roots
    }

    /// Returns the number of root nodes.
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Finds a node by object identifier.
    pub fn find(&self, object_id: u64) -> Option<&ForensicTreeNode> {
        for root in &self.roots {
            if let Some(node) = Self::find_node(root, object_id) {
                return Some(node);
            }
        }

        None
    }

    /// Recursively searches a node by object identifier.
    fn find_node(node: &ForensicTreeNode, object_id: u64) -> Option<&ForensicTreeNode> {
        if node.object_id == object_id {
            return Some(node);
        }

        for child in &node.children {
            if let Some(found) = Self::find_node(child, object_id) {
                return Some(found);
            }
        }

        None
    }

    /// Finds a node by its complete forensic path.
    ///
    /// The search starts at the roots and recursively traverses
    /// the common forensic tree.
    ///
    /// The path comparison is filesystem-independent.
    pub fn find_path(&self, path: &str) -> Option<&ForensicTreeNode> {
        let normalized = if path.is_empty() { "/" } else { path };

        for root in &self.roots {
            if let Some(found) = root.find_path(normalized) {
                return Some(found);
            }
        }

        None
    }
}

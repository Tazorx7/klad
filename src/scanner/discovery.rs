//! Single source of truth for "which files do we scan?".
//!
//! Every scanner used to run its own `WalkDir`, which meant the tree was
//! traversed three times and build artifacts / `.git` were read for secrets.
//! We now walk once, respect `.gitignore`, and prune obviously irrelevant
//! directories.

use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Directories that never contain scannable configuration and are expensive
/// to traverse. Everything else is left to `.gitignore`.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".terraform",
];

/// Collect every file worth scanning under `target`.
///
/// If `target` is a single file it is returned as-is, which keeps
/// `klad -p ./manifests/deployment.yaml` working.
pub fn discover(target: &Path) -> Vec<PathBuf> {
    if target.is_file() {
        return vec![target.to_path_buf()];
    }

    WalkBuilder::new(target)
        .hidden(false) // include `.env`, `.dockerignore`, etc.
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false) // reproducible across machines
        .require_git(false) // honour .gitignore even outside a repo
        .follow_links(false)
        .filter_entry(|entry| !is_skipped_dir(entry))
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .map(ignore::DirEntry::into_path)
        .collect()
}

fn is_skipped_dir(entry: &ignore::DirEntry) -> bool {
    entry.file_type().is_some_and(|t| t.is_dir())
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| SKIP_DIRS.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_vcs_and_dependency_dirs() {
        let dir = std::env::temp_dir().join("klad-discovery-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();

        std::fs::write(dir.join("src/Dockerfile"), "FROM scratch\n").unwrap();
        std::fs::write(dir.join("node_modules/Dockerfile"), "FROM scratch\n").unwrap();
        std::fs::write(dir.join(".git/Dockerfile"), "FROM scratch\n").unwrap();

        let found = discover(&dir);
        assert_eq!(found, vec![dir.join("src/Dockerfile")]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

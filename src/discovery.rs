//! Découverte hybride des racines de projets npm/yarn (SPEC-F03).

use std::path::{Path, PathBuf};

use indicatif::ProgressBar;

/// Un projet Node.js détecté par la présence d'un `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub root: PathBuf,
    pub has_npm_lock: bool,
    pub has_yarn_lock: bool,
}

/// Recherche récursivement tous les projets npm/yarn sous `root`. `progress` reflète
/// l'avancement du parcours de fichiers sous-jacent (SPEC-T02).
pub fn discover(root: &Path, progress: &ProgressBar) -> Vec<Project> {
    crate::walker::walk(root, progress)
        .filter(|entry| entry.file_name() == "package.json")
        .filter_map(|entry| entry.path().parent().map(Path::to_path_buf))
        .map(|dir| {
            let has_npm_lock = dir.join("package-lock.json").exists();
            let has_yarn_lock = dir.join("yarn.lock").exists();
            Project {
                root: dir,
                has_npm_lock,
                has_yarn_lock,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_a_project_with_npm_lock() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        let projects = discover(dir.path(), &ProgressBar::hidden());
        assert_eq!(projects.len(), 1);
        assert!(projects[0].has_npm_lock);
        assert!(!projects[0].has_yarn_lock);
    }
}

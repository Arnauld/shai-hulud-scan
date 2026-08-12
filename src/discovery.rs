//! Découverte hybride des racines de projets npm/yarn (SPEC-F03).

use std::path::{Path, PathBuf};

use indicatif::ProgressBar;
use tracing::debug;

/// Un projet Node.js détecté par la présence d'un `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub root: PathBuf,
    pub has_npm_lock: bool,
    pub has_yarn_lock: bool,
}

/// Recherche récursivement tous les projets npm/yarn sous `root`. `progress` reflète
/// l'avancement du parcours de fichiers sous-jacent (SPEC-T02). Les `package.json`
/// situés sous un `node_modules` sont exclus : ce sont des paquets déjà installés,
/// pas des racines de projet — ils sont vérifiés directement par leur nom/version
/// déclarés (`audit::audit_installed_packages`), sans lockfile ni simulation.
pub fn discover(root: &Path, progress: &ProgressBar) -> Vec<Project> {
    let projects: Vec<Project> = crate::walker::walk(root, progress)
        .filter(|entry| entry.file_name() == "package.json")
        .filter(|entry| {
            !entry
                .path()
                .components()
                .any(|component| component.as_os_str() == "node_modules")
        })
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
        .collect();

    for project in &projects {
        // DEBUG (pas INFO) : un projet par ligne inonderait la console par défaut sur
        // un gros workspace. Le décompte global reste visible via la barre de
        // progression (SPEC-T02/T04).
        debug!(
            project = %project.root.display(),
            npm_lock = project.has_npm_lock,
            yarn_lock = project.has_yarn_lock,
            "projet npm/yarn découvert"
        );
    }

    projects
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

    #[test]
    fn excludes_package_json_files_nested_under_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let installed_pkg_dir = dir.path().join("node_modules").join("some-dep");
        std::fs::create_dir_all(&installed_pkg_dir).unwrap();
        std::fs::write(installed_pkg_dir.join("package.json"), "{}").unwrap();

        let projects = discover(dir.path(), &ProgressBar::hidden());
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].root, dir.path());
    }
}

//! Découverte hybride des racines de projets npm/yarn (SPEC-F03).

use std::path::{Path, PathBuf};

use tracing::debug;

use crate::progress::DotProgress;

/// Un projet Node.js détecté par la présence d'un `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub root: PathBuf,
    pub has_npm_lock: bool,
    pub has_yarn_lock: bool,
}

/// Construit un `Project` à partir du chemin d'un `package.json` visité, s'il ne se
/// trouve pas sous un `node_modules` (paquet déjà installé, pas une racine de projet
/// — vérifié directement par nom/version déclarés, `audit::audit_installed_packages`,
/// sans lockfile ni simulation). Fonction pure sans notion de parcours : réutilisée à
/// la fois par [`discover`] (son propre parcours, pour compatibilité/tests unitaires)
/// et par `workspace::walk_workspace` (parcours unifié, SPEC-F02).
pub fn project_from_package_json(path: &Path) -> Option<Project> {
    if path.file_name().is_none_or(|name| name != "package.json") {
        return None;
    }
    if path
        .components()
        .any(|component| component.as_os_str() == "node_modules")
    {
        return None;
    }
    let dir = path.parent()?.to_path_buf();
    let has_npm_lock = dir.join("package-lock.json").exists();
    let has_yarn_lock = dir.join("yarn.lock").exists();
    Some(Project {
        root: dir,
        has_npm_lock,
        has_yarn_lock,
    })
}

/// Recherche récursivement tous les projets npm/yarn sous `root`. `progress` reflète
/// l'avancement du parcours de fichiers sous-jacent (SPEC-T02). Effectue son propre
/// parcours (conservée pour compatibilité/tests unitaires en isolation) — le chemin de
/// production (`lib.rs::run`) passe par `workspace::walk_workspace`, qui appelle
/// [`project_from_package_json`] pour chaque entrée d'un unique parcours partagé avec
/// le scan passif (SPEC-F05/F08), plutôt que de parcourir le disque une seconde fois.
pub fn discover(root: &Path, progress: &DotProgress, no_ignore: bool) -> Vec<Project> {
    let projects: Vec<Project> = crate::walker::walk(root, progress, no_ignore)
        .filter_map(|entry| project_from_package_json(entry.path()))
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

        let projects = discover(dir.path(), &DotProgress::new(false), false);
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

        let projects = discover(dir.path(), &DotProgress::new(false), false);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].root, dir.path());
    }
}

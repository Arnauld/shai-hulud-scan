//! Recherche active de signaux malveillants connus sur le disque (SPEC-F06/F07).
//!
//! Ces listes évoluent vite avec les campagnes ; elles sont volontairement regroupées
//! ici pour être externalisables plus tard vers un fichier de config (`iocs.toml`)
//! sans toucher au reste du moteur de Threat Hunting.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::discovery::Project;

/// Fichiers de charge utile connus, recherchés à la racine du workspace et des projets.
pub const SUSPICIOUS_FILENAMES: &[&str] = &[
    "setup.mjs",
    "Math_Symbol.js",
    "setup_bun.js",
    "bun_environment.js",
];

/// Chaîne recherchée dans les hooks de `<pkg_dir>/node_modules/*/package.json`.
pub const SUSPICIOUS_HOOK_MARKER: &str = "setup.mjs";

/// Chaîne recherchée dans les LaunchAgents macOS (`~/Library/LaunchAgents/`).
pub const SUSPICIOUS_LAUNCH_AGENT_MARKER: &str = "gh-token-monitor";

/// Fichiers d'exfiltration générés localement par la vague "Second Coming" (SPEC-F07).
pub const EXFIL_ARTIFACT_FILENAMES: &[&str] = &[
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json",
    "actionsSecrets.json",
    "data.json",
];

/// Noms de workflows GitHub Actions malveillants connus, injectés dans `.github/workflows/`.
pub const SUSPICIOUS_WORKFLOW_FILENAMES: &[&str] = &["shai-hulud-workflow.yml", "discussion.yaml"];

/// Dossier de cache caché utilisé pour dissimuler un binaire TruffleHog détourné.
pub const SUSPICIOUS_CACHE_DIRNAME: &str = ".truffler-cache";

/// Catégorie d'un signal de compromission détecté sur le disque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ThreatCategory {
    SuspiciousFile,
    SuspiciousHook,
    ExfilArtifact,
    SuspiciousWorkflow,
    SuspiciousCacheDir,
    LaunchAgent,
}

/// Un signal de compromission détecté sur le disque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThreatSignal {
    pub category: ThreatCategory,
    pub path: PathBuf,
    pub detail: String,
}

/// Exécute l'ensemble des vérifications de Threat Hunting (SPEC-F06/F07) sur le
/// workspace et chaque projet Node.js identifié.
pub fn hunt(workspace_root: &Path, projects: &[Project]) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();

    signals.extend(scan_root(workspace_root));
    signals.extend(scan_github_workflows(workspace_root));

    for project in projects {
        signals.extend(scan_root(&project.root));
        signals.extend(scan_github_workflows(&project.root));
        signals.extend(scan_node_modules_hooks(&project.root));
    }

    signals.extend(scan_root_for_known_files(
        &std::env::temp_dir(),
        EXFIL_ARTIFACT_FILENAMES,
        ThreatCategory::ExfilArtifact,
    ));
    signals.extend(scan_macos_launch_agents());

    signals.sort_by(|a, b| a.path.cmp(&b.path));
    signals.dedup();
    signals
}

fn scan_root(root: &Path) -> Vec<ThreatSignal> {
    let mut signals =
        scan_root_for_known_files(root, SUSPICIOUS_FILENAMES, ThreatCategory::SuspiciousFile);
    signals.extend(scan_root_for_known_files(
        root,
        EXFIL_ARTIFACT_FILENAMES,
        ThreatCategory::ExfilArtifact,
    ));
    signals.extend(scan_cache_dir(root));
    signals
}

fn scan_root_for_known_files(
    root: &Path,
    filenames: &[&str],
    category: ThreatCategory,
) -> Vec<ThreatSignal> {
    filenames
        .iter()
        .map(|name| root.join(name))
        .filter(|path| path.is_file())
        .map(|path| ThreatSignal {
            category,
            detail: format!("fichier suspect connu : {}", path.display()),
            path,
        })
        .collect()
}

fn scan_cache_dir(root: &Path) -> Option<ThreatSignal> {
    let path = root.join(SUSPICIOUS_CACHE_DIRNAME);
    path.is_dir().then(|| ThreatSignal {
        detail: format!("dossier de cache suspect connu : {}", path.display()),
        category: ThreatCategory::SuspiciousCacheDir,
        path,
    })
}

/// Vérifie les hooks de `<pkg_dir>/node_modules/*/package.json` (et des paquets
/// scopés `@scope/*`) sans parcours complet du disque (SPEC-F06, O(1) par projet).
fn scan_node_modules_hooks(project_root: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    let Ok(entries) = std::fs::read_dir(project_root.join("node_modules")) else {
        return signals;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with('@') {
            let Ok(scoped_entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for scoped_entry in scoped_entries.flatten() {
                check_hook_file(&scoped_entry.path().join("package.json"), &mut signals);
            }
        } else {
            check_hook_file(&path.join("package.json"), &mut signals);
        }
    }

    signals
}

fn check_hook_file(package_json: &Path, signals: &mut Vec<ThreatSignal>) {
    let Ok(content) = std::fs::read_to_string(package_json) else {
        return;
    };
    if content.contains(SUSPICIOUS_HOOK_MARKER) {
        signals.push(ThreatSignal {
            category: ThreatCategory::SuspiciousHook,
            detail: format!("hook suspect détecté ({SUSPICIOUS_HOOK_MARKER})"),
            path: package_json.to_path_buf(),
        });
    }
}

fn scan_github_workflows(root: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join(".github").join("workflows")) else {
        return signals;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if SUSPICIOUS_WORKFLOW_FILENAMES.contains(&file_name.to_string_lossy().as_ref()) {
            signals.push(ThreatSignal {
                category: ThreatCategory::SuspiciousWorkflow,
                detail: "nom de workflow GitHub Actions malveillant connu".to_string(),
                path: entry.path(),
            });
        }
    }

    signals
}

/// Recherche un LaunchAgent macOS suspect dans `~/Library/LaunchAgents/` (SPEC-F06).
pub fn scan_macos_launch_agents() -> Vec<ThreatSignal> {
    match dirs::home_dir() {
        Some(home) => scan_launch_agents_dir(&home.join("Library").join("LaunchAgents")),
        None => Vec::new(),
    }
}

fn scan_launch_agents_dir(dir: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return signals;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains(SUSPICIOUS_LAUNCH_AGENT_MARKER) {
            signals.push(ThreatSignal {
                category: ThreatCategory::LaunchAgent,
                detail: format!("LaunchAgent suspect ({SUSPICIOUS_LAUNCH_AGENT_MARKER})"),
                path,
            });
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_suspicious_files_at_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.mjs"), "").unwrap();
        std::fs::write(dir.path().join("harmless.js"), "").unwrap();

        let signals = scan_root(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::SuspiciousFile);
        assert!(signals[0].path.ends_with("setup.mjs"));
    }

    #[test]
    fn detects_exfil_artifacts_and_cache_dir_at_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cloud.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join(SUSPICIOUS_CACHE_DIRNAME)).unwrap();

        let signals = scan_root(dir.path());
        assert!(signals
            .iter()
            .any(|s| s.category == ThreatCategory::ExfilArtifact));
        assert!(signals
            .iter()
            .any(|s| s.category == ThreatCategory::SuspiciousCacheDir));
    }

    #[test]
    fn detects_suspicious_hook_in_node_modules_including_scoped_packages() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("node_modules").join("evil-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"scripts":{"postinstall":"node setup.mjs"}}"#,
        )
        .unwrap();

        let scoped_dir = dir
            .path()
            .join("node_modules")
            .join("@scope")
            .join("evil-scoped");
        std::fs::create_dir_all(&scoped_dir).unwrap();
        std::fs::write(
            scoped_dir.join("package.json"),
            r#"{"scripts":{"postinstall":"node setup.mjs"}}"#,
        )
        .unwrap();

        let clean_dir = dir.path().join("node_modules").join("safe-pkg");
        std::fs::create_dir_all(&clean_dir).unwrap();
        std::fs::write(clean_dir.join("package.json"), r#"{"name":"safe-pkg"}"#).unwrap();

        let signals = scan_node_modules_hooks(dir.path());
        assert_eq!(signals.len(), 2);
        assert!(signals
            .iter()
            .all(|s| s.category == ThreatCategory::SuspiciousHook));
    }

    #[test]
    fn detects_malicious_github_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("shai-hulud-workflow.yml"), "").unwrap();
        std::fs::write(workflows.join("ci.yml"), "").unwrap();

        let signals = scan_github_workflows(dir.path());
        assert_eq!(signals.len(), 1);
        assert!(signals[0].path.ends_with("shai-hulud-workflow.yml"));
    }

    #[test]
    fn detects_suspicious_launch_agent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("com.suspicious.agent.plist"),
            "gh-token-monitor",
        )
        .unwrap();
        std::fs::write(dir.path().join("com.safe.agent.plist"), "harmless").unwrap();

        let signals = scan_launch_agents_dir(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::LaunchAgent);
    }

    #[test]
    fn hunt_deduplicates_signals_shared_by_workspace_root_and_project_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.mjs"), "").unwrap();
        let projects = vec![Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: false,
            has_yarn_lock: false,
        }];

        let signals = hunt(dir.path(), &projects);
        assert_eq!(
            signals
                .iter()
                .filter(|s| s.category == ThreatCategory::SuspiciousFile)
                .count(),
            1
        );
    }
}

//! Détection de détournement de registre npm/yarn (SPEC-F08) : valide le champ
//! `resolved` de chaque dépendance verrouillée contre l'allowlist des registres
//! officiels attendus.

use std::path::Path;

use crate::discovery::Project;
use crate::hunt::{ThreatCategory, ThreatSignal};
use crate::lockfile::{parse_npm_lock, parse_yarn_lock, LockedDependency};

/// Hôtes de registre officiels attendus (SPEC-F08) : toute URL `resolved` pointant
/// ailleurs est un signal de détournement (registre privé compromis, proxy
/// malveillant substitué au registre officiel).
pub const ALLOWED_REGISTRY_HOSTS: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];

/// Vrai si `url` pointe vers un hôte de registre autorisé (SPEC-F08).
pub fn is_allowed_registry_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or_default();
    ALLOWED_REGISTRY_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn hijacked_registry_signals(deps: &[LockedDependency], lockfile_path: &Path) -> Vec<ThreatSignal> {
    deps.iter()
        .filter_map(|dep| {
            let resolved = dep.resolved.as_ref()?;
            if is_allowed_registry_url(resolved) {
                return None;
            }
            Some(ThreatSignal {
                category: ThreatCategory::HijackedRegistry,
                detail: format!(
                    "{}@{} résolu depuis un registre non autorisé : {resolved}",
                    dep.name, dep.version
                ),
                path: lockfile_path.to_path_buf(),
            })
        })
        .collect()
}

/// Vérifie les lockfiles existants d'un projet (SPEC-F04, niveau 1) pour un
/// détournement de registre (SPEC-F08).
pub fn scan_project(project: &Project) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();

    if project.has_npm_lock {
        let path = project.root.join("package-lock.json");
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(deps) = parse_npm_lock(&content) {
                signals.extend(hijacked_registry_signals(&deps, &path));
            }
        }
    }

    if project.has_yarn_lock {
        let path = project.root.join("yarn.lock");
        if let Ok(content) = std::fs::read_to_string(&path) {
            let deps = parse_yarn_lock(&content);
            signals.extend(hijacked_registry_signals(&deps, &path));
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_the_official_npm_and_yarn_registries() {
        assert!(is_allowed_registry_url(
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        ));
        assert!(is_allowed_registry_url(
            "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
        ));
    }

    #[test]
    fn rejects_an_unofficial_registry_host() {
        assert!(!is_allowed_registry_url(
            "https://evil-mirror.example.com/lodash/-/lodash-4.17.21.tgz"
        ));
        assert!(!is_allowed_registry_url("not a url"));
    }

    #[test]
    fn flags_a_dependency_resolved_from_an_unofficial_registry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo" },
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                    },
                    "node_modules/evil-pkg": {
                        "version": "1.0.0",
                        "resolved": "https://evil-mirror.example.com/evil-pkg-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: true,
            has_yarn_lock: false,
        };

        let signals = scan_project(&project);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::HijackedRegistry);
        assert!(signals[0].detail.contains("evil-pkg"));
    }

    #[test]
    fn no_signal_when_no_lockfile_present() {
        let dir = tempfile::tempdir().unwrap();
        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: false,
            has_yarn_lock: false,
        };

        assert!(scan_project(&project).is_empty());
    }
}

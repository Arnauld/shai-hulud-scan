//! Audit double-niveau des projets NPM/Yarn : lockfile existant + simulation (SPEC-F04).

use std::path::{Path, PathBuf};

use indicatif::ProgressBar;
use serde::Deserialize;
use tracing::debug;

use crate::discovery::Project;
use crate::ioc::{CompromiseStatus, IocDatabase};
use crate::lockfile::{parse_npm_lock, parse_yarn_lock};

/// Une dépendance résolue dans un lockfile, avec son verdict et le projet qui la
/// référence (SPEC-F04, niveau 1) — nécessaire pour regrouper le récapitulatif des
/// dépendances problématiques par projet (SPEC-T05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub project: PathBuf,
    pub package: String,
    pub version: String,
    pub status: CompromiseStatus,
}

/// Vérifie une dépendance par rapport à la base IOC (SPEC-F04, niveau 1).
pub fn check_dependency(
    db: &IocDatabase,
    project_root: &Path,
    package: &str,
    version: &str,
) -> Finding {
    let status = db.evaluate_compromise(package, version);
    debug!(package, version, status = ?status, "dépendance auditée");
    Finding {
        project: project_root.to_path_buf(),
        package: package.to_string(),
        version: version.to_string(),
        status,
    }
}

/// Audite un projet : parsing des lockfiles NPM (v1/v2/v3) / Yarn (Classic/Berry)
/// existants et vérification contre l'IOC (SPEC-F04, niveau 1). La simulation
/// `npm install --package-lock-only` isolée (niveau 2) reste à implémenter.
pub fn audit_project(db: &IocDatabase, project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();

    if project.has_npm_lock {
        if let Ok(content) = std::fs::read_to_string(project.root.join("package-lock.json")) {
            if let Ok(deps) = parse_npm_lock(&content) {
                findings.extend(
                    deps.iter()
                        .map(|dep| check_dependency(db, &project.root, &dep.name, &dep.version)),
                );
            }
        }
    }

    if project.has_yarn_lock {
        if let Ok(content) = std::fs::read_to_string(project.root.join("yarn.lock")) {
            let deps = parse_yarn_lock(&content);
            findings.extend(
                deps.iter()
                    .map(|dep| check_dependency(db, &project.root, &dep.name, &dep.version)),
            );
        }
    }

    findings
}

#[derive(Debug, Deserialize)]
struct InstalledPackageManifest {
    name: Option<String>,
    version: Option<String>,
}

/// Vérifie directement les paquets déjà installés dans `<project.root>/node_modules`
/// par le nom et la version déclarés dans leur propre `package.json` — ce sont des
/// paquets déjà résolus sur disque, pas des racines de projet : inutile de générer
/// ou simuler un lockfile pour eux (amélioration de SPEC-F04, niveau 1). Parcourt
/// `node_modules` à toute profondeur (contrairement au scan de hooks O(1) de
/// SPEC-F06) afin de couvrir aussi les dépendances transitives non hissées
/// (`node_modules` imbriqués suite à un conflit de version).
pub fn audit_installed_packages(db: &IocDatabase, project: &Project) -> Vec<Finding> {
    let node_modules = project.root.join("node_modules");
    if !node_modules.is_dir() {
        // Cas normal (pas une erreur) : le projet n'a simplement pas encore été
        // installé. Éviter d'appeler le walker sur un chemin absent, qui
        // journalise sinon un WARN d'erreur d'E/S trompeur pour ce cas courant.
        return Vec::new();
    }
    let progress = ProgressBar::hidden();
    crate::walker::walk(&node_modules, &progress)
        .filter(|entry| entry.file_name() == "package.json")
        .filter_map(|entry| {
            let content = std::fs::read_to_string(entry.path()).ok()?;
            let manifest: InstalledPackageManifest = serde_json::from_str(&content).ok()?;
            Some(check_dependency(
                db,
                &project.root,
                &manifest.name?,
                &manifest.version?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_an_exact_version_match_as_corrompue() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();
        assert!(matches!(
            check_dependency(&db, Path::new("/proj"), "evil-pkg", "1.0.0").status,
            CompromiseStatus::Corrompue { .. }
        ));
    }

    #[test]
    fn flags_a_known_package_at_a_different_version_as_vulnerable_not_sain() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();
        assert!(matches!(
            check_dependency(&db, Path::new("/proj"), "evil-pkg", "2.0.0").status,
            CompromiseStatus::Vulnerable { .. }
        ));
    }

    #[test]
    fn flags_a_fully_unknown_package_as_sain() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();
        assert_eq!(
            check_dependency(&db, Path::new("/proj"), "unrelated-pkg", "2.0.0").status,
            CompromiseStatus::Sain
        );
    }

    #[test]
    fn check_dependency_records_the_originating_project() {
        let db = IocDatabase::default();
        let finding = check_dependency(&db, Path::new("/projects/demo"), "pkg", "1.0.0");
        assert_eq!(finding.project, PathBuf::from("/projects/demo"));
    }

    #[test]
    fn audits_a_project_with_a_compromised_npm_lock_dependency() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo" },
                    "node_modules/evil-pkg": { "version": "1.0.0" },
                    "node_modules/safe-pkg": { "version": "9.9.9" }
                }
            }"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: true,
            has_yarn_lock: false,
        };

        let findings = audit_project(&db, &project);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.project == project.root));
        assert!(findings
            .iter()
            .any(|f| f.package == "evil-pkg"
                && matches!(f.status, CompromiseStatus::Corrompue { .. })));
        assert!(findings
            .iter()
            .any(|f| f.package == "safe-pkg" && f.status == CompromiseStatus::Sain));
    }

    #[test]
    fn audits_installed_packages_directly_from_their_own_package_json() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let evil_dir = dir.path().join("node_modules").join("evil-pkg");
        std::fs::create_dir_all(&evil_dir).unwrap();
        std::fs::write(
            evil_dir.join("package.json"),
            r#"{"name":"evil-pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        let safe_dir = dir.path().join("node_modules").join("safe-pkg");
        std::fs::create_dir_all(&safe_dir).unwrap();
        std::fs::write(
            safe_dir.join("package.json"),
            r#"{"name":"safe-pkg","version":"9.9.9"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: false,
            has_yarn_lock: false,
        };

        let findings = audit_installed_packages(&db, &project);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.project == project.root));
        assert!(findings
            .iter()
            .any(|f| f.package == "evil-pkg"
                && matches!(f.status, CompromiseStatus::Corrompue { .. })));
        assert!(findings
            .iter()
            .any(|f| f.package == "safe-pkg" && f.status == CompromiseStatus::Sain));
    }

    #[test]
    fn audits_deeply_nested_transitive_dependencies() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();

        let dir = tempfile::tempdir().unwrap();
        // node_modules/foo/node_modules/evil-pkg : dépendance transitive non hissée,
        // typiquement due à un conflit de version avec la copie hissée à la racine.
        let nested_dir = dir
            .path()
            .join("node_modules")
            .join("foo")
            .join("node_modules")
            .join("evil-pkg");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(
            nested_dir.join("package.json"),
            r#"{"name":"evil-pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: false,
            has_yarn_lock: false,
        };

        let findings = audit_installed_packages(&db, &project);
        assert!(findings
            .iter()
            .any(|f| f.package == "evil-pkg"
                && matches!(f.status, CompromiseStatus::Corrompue { .. })));
    }
}

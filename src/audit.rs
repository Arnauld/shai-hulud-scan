//! Audit double-niveau des projets NPM/Yarn : lockfile existant + simulation (SPEC-F04).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

use crate::discovery::Project;
use crate::hunt::{ThreatCategory, ThreatSignal};
use crate::ioc::{CompromiseStatus, IocDatabase};
use crate::lockfile::{parse_npm_lock, parse_yarn_lock, LockedDependency};
use crate::progress::DotProgress;

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
/// (`node_modules` imbriqués suite à un conflit de version). `threads` fixe le nombre
/// de threads du parcours (`--walk-threads`, `0` = auto).
pub fn audit_installed_packages(
    db: &IocDatabase,
    project: &Project,
    threads: usize,
) -> Vec<Finding> {
    let node_modules = project.root.join("node_modules");
    if !node_modules.is_dir() {
        // Cas normal (pas une erreur) : le projet n'a simplement pas encore été
        // installé. Éviter d'appeler le walker sur un chemin absent, qui
        // journalise sinon un WARN d'erreur d'E/S trompeur pour ce cas courant.
        return Vec::new();
    }
    let progress = DotProgress::new_disabled();
    crate::walker::walk(&node_modules, &progress, true, threads)
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

/// Verrouille une version par nom de paquet à partir des lockfiles existants du
/// projet (SPEC-F04, niveau 1) — nécessaire pour la détection de divergence
/// lockfile / installé (SPEC-F08). Un nom référencé à plusieurs versions distinctes
/// dans le(s) lockfile(s) (résolution multi-version légitime d'un paquet transitif
/// non hissé) est volontairement exclu : impossible de savoir sans profondeur de
/// l'arbre à quelle copie installée le comparer, mieux vaut ne rien signaler que de
/// produire un faux positif.
fn locked_versions(project: &Project) -> HashMap<String, String> {
    let mut versions: HashMap<String, HashSet<String>> = HashMap::new();
    let mut record = |dep: LockedDependency| {
        versions.entry(dep.name).or_default().insert(dep.version);
    };

    if project.has_npm_lock {
        if let Ok(content) = std::fs::read_to_string(project.root.join("package-lock.json")) {
            if let Ok(deps) = parse_npm_lock(&content) {
                deps.into_iter().for_each(&mut record);
            }
        }
    }

    if project.has_yarn_lock {
        if let Ok(content) = std::fs::read_to_string(project.root.join("yarn.lock")) {
            parse_yarn_lock(&content).into_iter().for_each(&mut record);
        }
    }

    versions
        .into_iter()
        .filter_map(|(name, distinct_versions)| {
            (distinct_versions.len() == 1)
                .then(|| (name, distinct_versions.into_iter().next().unwrap()))
        })
        .collect()
}

/// Chemins des `package.json` des paquets installés au premier niveau de
/// `node_modules` (paquets hissés, gère l'espace de noms `@scope/`) — volontairement
/// **pas** récursif dans les `node_modules` imbriqués, à la différence de
/// [`audit_installed_packages`] : une version différente en profondeur reflète une
/// résolution multi-version normale de npm/yarn, pas une divergence à signaler.
fn top_level_package_json_paths(node_modules: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let Ok(entries) = std::fs::read_dir(node_modules) else {
        return paths;
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
            paths.extend(
                scoped_entries
                    .flatten()
                    .map(|scoped| scoped.path().join("package.json"))
                    .filter(|manifest| manifest.is_file()),
            );
            continue;
        }

        let manifest = path.join("package.json");
        if manifest.is_file() {
            paths.push(manifest);
        }
    }

    paths
}

/// Compare les versions déclarées dans le(s) lockfile(s) existant(s) avec celles
/// réellement présentes dans `node_modules` (SPEC-F08) : une divergence peut trahir
/// un `node_modules` désynchronisé du lockfile, ou un paquet substitué en dehors du
/// contrôle de ce dernier (contournement du verrouillage de version).
pub fn audit_lockfile_drift(project: &Project) -> Vec<ThreatSignal> {
    let locked = locked_versions(project);
    if locked.is_empty() {
        return Vec::new();
    }

    let node_modules = project.root.join("node_modules");
    if !node_modules.is_dir() {
        return Vec::new();
    }

    top_level_package_json_paths(&node_modules)
        .into_iter()
        .filter_map(|manifest_path| {
            let content = std::fs::read_to_string(&manifest_path).ok()?;
            let manifest: InstalledPackageManifest = serde_json::from_str(&content).ok()?;
            let name = manifest.name?;
            let installed_version = manifest.version?;
            let locked_version = locked.get(&name)?;
            (locked_version != &installed_version).then(|| ThreatSignal {
                category: ThreatCategory::LockfileDrift,
                detail: format!(
                    "{name}@{installed_version} installé, mais le lockfile référence {name}@{locked_version}"
                ),
                path: manifest_path,
            })
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

        let findings = audit_installed_packages(&db, &project, 0);
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

        let findings = audit_installed_packages(&db, &project, 0);
        assert!(findings
            .iter()
            .any(|f| f.package == "evil-pkg"
                && matches!(f.status, CompromiseStatus::Corrompue { .. })));
    }

    #[test]
    fn flags_a_package_installed_at_a_different_version_than_the_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo" },
                    "node_modules/lodash": { "version": "4.17.21" }
                }
            }"#,
        )
        .unwrap();

        let installed_dir = dir.path().join("node_modules").join("lodash");
        std::fs::create_dir_all(&installed_dir).unwrap();
        std::fs::write(
            installed_dir.join("package.json"),
            r#"{"name":"lodash","version":"4.17.20"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: true,
            has_yarn_lock: false,
        };

        let signals = audit_lockfile_drift(&project);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::LockfileDrift);
        assert!(signals[0].detail.contains("4.17.20"));
        assert!(signals[0].detail.contains("4.17.21"));
    }

    #[test]
    fn no_drift_signal_when_installed_version_matches_the_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo" },
                    "node_modules/lodash": { "version": "4.17.21" }
                }
            }"#,
        )
        .unwrap();

        let installed_dir = dir.path().join("node_modules").join("lodash");
        std::fs::create_dir_all(&installed_dir).unwrap();
        std::fs::write(
            installed_dir.join("package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: true,
            has_yarn_lock: false,
        };

        assert!(audit_lockfile_drift(&project).is_empty());
    }

    #[test]
    fn ignores_a_package_name_locked_at_multiple_distinct_versions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo" },
                    "node_modules/lodash": { "version": "4.17.21" },
                    "node_modules/foo/node_modules/lodash": { "version": "3.10.1" }
                }
            }"#,
        )
        .unwrap();

        let installed_dir = dir.path().join("node_modules").join("lodash");
        std::fs::create_dir_all(&installed_dir).unwrap();
        std::fs::write(
            installed_dir.join("package.json"),
            r#"{"name":"lodash","version":"9.9.9"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: true,
            has_yarn_lock: false,
        };

        // Ambigu (deux versions verrouillées pour le même nom) : on ne peut pas
        // savoir laquelle comparer à la copie hissée, donc aucun signal.
        assert!(audit_lockfile_drift(&project).is_empty());
    }

    #[test]
    fn detects_drift_for_a_scoped_package() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo" },
                    "node_modules/@scope/pkg": { "version": "1.0.0" }
                }
            }"#,
        )
        .unwrap();

        let installed_dir = dir.path().join("node_modules").join("@scope").join("pkg");
        std::fs::create_dir_all(&installed_dir).unwrap();
        std::fs::write(
            installed_dir.join("package.json"),
            r#"{"name":"@scope/pkg","version":"2.0.0"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: true,
            has_yarn_lock: false,
        };

        let signals = audit_lockfile_drift(&project);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].detail.contains("@scope/pkg"));
    }

    #[test]
    fn no_signal_when_no_lockfile_present() {
        let dir = tempfile::tempdir().unwrap();
        let installed_dir = dir.path().join("node_modules").join("lodash");
        std::fs::create_dir_all(&installed_dir).unwrap();
        std::fs::write(
            installed_dir.join("package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        )
        .unwrap();

        let project = Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: false,
            has_yarn_lock: false,
        };

        assert!(audit_lockfile_drift(&project).is_empty());
    }
}

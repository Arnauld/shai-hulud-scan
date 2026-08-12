//! Audit double-niveau des projets NPM/Yarn : lockfile existant + simulation (SPEC-F04).

use serde::Deserialize;

use crate::discovery::Project;
use crate::hunt::installed_package_manifests;
use crate::ioc::IocDatabase;
use crate::lockfile::{parse_npm_lock, parse_yarn_lock};

/// Verdict d'audit d'une dépendance vis-à-vis de la base IOC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Vulnerable,
    Sain,
}

/// Une dépendance résolue dans un lockfile, avec son verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub package: String,
    pub version: String,
    pub status: Status,
}

/// Vérifie une dépendance par rapport à la base IOC (SPEC-F04, niveau 1).
pub fn check_dependency(db: &IocDatabase, package: &str, version: &str) -> Finding {
    let status = if db.is_compromised(package, version) {
        Status::Vulnerable
    } else {
        Status::Sain
    };
    Finding {
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
                        .map(|dep| check_dependency(db, &dep.name, &dep.version)),
                );
            }
        }
    }

    if project.has_yarn_lock {
        if let Ok(content) = std::fs::read_to_string(project.root.join("yarn.lock")) {
            let deps = parse_yarn_lock(&content);
            findings.extend(
                deps.iter()
                    .map(|dep| check_dependency(db, &dep.name, &dep.version)),
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
/// ou simuler un lockfile pour eux (amélioration de SPEC-F04, niveau 1).
pub fn audit_installed_packages(db: &IocDatabase, project: &Project) -> Vec<Finding> {
    installed_package_manifests(&project.root)
        .iter()
        .filter_map(|manifest_path| {
            let content = std::fs::read_to_string(manifest_path).ok()?;
            let manifest: InstalledPackageManifest = serde_json::from_str(&content).ok()?;
            Some(check_dependency(db, &manifest.name?, &manifest.version?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_a_compromised_dependency() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();
        assert_eq!(
            check_dependency(&db, "evil-pkg", "1.0.0").status,
            Status::Vulnerable
        );
        assert_eq!(
            check_dependency(&db, "evil-pkg", "2.0.0").status,
            Status::Sain
        );
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
        assert!(findings
            .iter()
            .any(|f| f.package == "evil-pkg" && f.status == Status::Vulnerable));
        assert!(findings
            .iter()
            .any(|f| f.package == "safe-pkg" && f.status == Status::Sain));
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
        assert!(findings
            .iter()
            .any(|f| f.package == "evil-pkg" && f.status == Status::Vulnerable));
        assert!(findings
            .iter()
            .any(|f| f.package == "safe-pkg" && f.status == Status::Sain));
    }
}

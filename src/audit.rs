//! Audit double-niveau des projets NPM/Yarn : lockfile existant + simulation (SPEC-F04).

use crate::discovery::Project;
use crate::ioc::IocDatabase;

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

/// Audite un projet : parsing des lockfiles NPM (v1/v2/v3) / Yarn (Classic/Berry) puis,
/// en niveau 2, simulation `npm install --package-lock-only` isolée (SPEC-F04). Le
/// parsing des lockfiles et la simulation restent à implémenter.
pub fn audit_project(_db: &IocDatabase, _project: &Project) -> Vec<Finding> {
    Vec::new()
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
}

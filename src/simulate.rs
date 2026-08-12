//! Simulation `npm install --package-lock-only` isolée pour évaluer les dépendances
//! qui seraient résolues aujourd'hui, sans modifier durablement le dépôt (SPEC-F04,
//! niveau 2). Le nombre de processus npm concurrents est borné par un sémaphore
//! (SPEC-T01) pour éviter de saturer le disque/les E/S, en particulier sous WSL.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::audit::{check_dependency, Finding};
use crate::discovery::Project;
use crate::ioc::IocDatabase;
use crate::lockfile::parse_npm_lock;

const NPM_ARGS: &[&str] = &[
    "install",
    "--package-lock-only",
    "--include=dev",
    "--ignore-scripts",
    "--audit=false",
    "--fund=false",
    "--legacy-peer-deps",
    "--no-workspaces",
];

/// Noms des fichiers sauvegardés/restaurés autour de la simulation. `npm install`
/// peut réécrire un `yarn.lock` existant en effet de bord (constaté en pratique),
/// pas seulement générer/modifier `package-lock.json` : les deux doivent être
/// protégés (SPEC-F04 — "restaurer proprement l'état d'origine du répertoire").
const PROTECTED_LOCKFILES: &[&str] = &["package-lock.json", "yarn.lock"];

/// Simule `npm install` dans `project.root` et retourne les dépendances qui seraient
/// résolues aujourd'hui, vérifiées contre la base IOC. Le répertoire du projet est
/// restauré à l'identique une fois l'analyse terminée, y compris en cas d'échec ou de
/// dépassement de `npm_timeout` (SPEC-F04).
pub async fn simulate_install(
    project: &Project,
    db: &IocDatabase,
    semaphore: &Semaphore,
    npm_timeout: Duration,
) -> anyhow::Result<Vec<Finding>> {
    run_simulation(project, db, semaphore, npm_timeout, run_npm_install).await
}

/// Lance `npm install` avec stdout/stderr capturés (jamais hérités du process
/// parent) : la sortie de npm ne doit jamais fuiter sur la console de
/// shai-hulud-guard, elle est journalisée en DEBUG pour le diagnostic (SPEC-T04).
async fn run_npm_install(root: PathBuf) -> std::io::Result<()> {
    let output = Command::new("npm")
        .args(NPM_ARGS)
        .current_dir(&root)
        .output()
        .await?;

    if !output.stdout.is_empty() {
        debug!(
            project = %root.display(),
            stdout = %String::from_utf8_lossy(&output.stdout),
            "sortie npm install"
        );
    }
    if !output.stderr.is_empty() {
        debug!(
            project = %root.display(),
            stderr = %String::from_utf8_lossy(&output.stderr),
            "sortie npm install"
        );
    }

    Ok(())
}

/// Sauvegarde d'un fichier avant simulation, restauré (ou supprimé s'il n'existait
/// pas) une fois la simulation terminée.
struct LockfileBackup {
    original_path: PathBuf,
    backup_path: PathBuf,
    had_original: bool,
}

impl LockfileBackup {
    async fn create(original_path: PathBuf) -> std::io::Result<Self> {
        let mut backup_path = original_path.clone();
        let backup_name = format!(
            "{}.orig",
            original_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        backup_path.set_file_name(backup_name);

        let had_original = original_path.exists();
        if had_original {
            tokio::fs::rename(&original_path, &backup_path).await?;
        }

        Ok(Self {
            original_path,
            backup_path,
            had_original,
        })
    }

    async fn restore(&self) -> std::io::Result<()> {
        if self.had_original {
            tokio::fs::rename(&self.backup_path, &self.original_path).await
        } else if self.original_path.exists() {
            tokio::fs::remove_file(&self.original_path).await
        } else {
            Ok(())
        }
    }
}

/// Cœur testable de la simulation : `command` est injecté pour permettre de tester
/// la logique de sauvegarde/restauration et d'analyse sans dépendre d'un vrai `npm`.
async fn run_simulation<F, Fut>(
    project: &Project,
    db: &IocDatabase,
    semaphore: &Semaphore,
    npm_timeout: Duration,
    command: F,
) -> anyhow::Result<Vec<Finding>>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let mut backups = Vec::with_capacity(PROTECTED_LOCKFILES.len());
    for filename in PROTECTED_LOCKFILES {
        backups.push(LockfileBackup::create(project.root.join(filename)).await?);
    }

    let permit = semaphore.acquire().await?;
    let outcome = match tokio::time::timeout(npm_timeout, command(project.root.clone())).await {
        Ok(result) => result,
        Err(_) => {
            warn!(
                project = %project.root.display(),
                timeout_secs = npm_timeout.as_secs(),
                "simulation npm install : délai dépassé, abandon"
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "npm install a dépassé le délai imparti",
            ))
        }
    };
    drop(permit);

    if let Err(ref err) = outcome {
        warn!(
            project = %project.root.display(),
            error = %err,
            "simulation npm install échouée"
        );
    }

    let lock_path = project.root.join("package-lock.json");
    let findings = if outcome.is_ok() {
        match tokio::fs::read_to_string(&lock_path).await {
            Ok(content) => parse_npm_lock(&content)
                .map(|deps| {
                    deps.iter()
                        .map(|dep| check_dependency(db, &dep.name, &dep.version))
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    for backup in &backups {
        backup.restore().await?;
    }

    outcome?;
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_TIMEOUT: Duration = Duration::from_secs(30);

    fn project(root: PathBuf) -> Project {
        Project {
            root,
            has_npm_lock: false,
            has_yarn_lock: false,
        }
    }

    #[tokio::test]
    async fn analyzes_the_simulated_lockfile_and_removes_it_when_no_original_existed() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let semaphore = Semaphore::new(1);

        let findings = run_simulation(
            &project(dir.path().to_path_buf()),
            &db,
            &semaphore,
            NO_TIMEOUT,
            |root| async move {
                std::fs::write(
                    root.join("package-lock.json"),
                    r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/evil-pkg":{"version":"1.0.0"}}}"#,
                )
                .unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, crate::audit::Status::Vulnerable);
        assert!(!dir.path().join("package-lock.json").exists());
        assert!(!dir.path().join("package-lock.json.orig").exists());
    }

    #[tokio::test]
    async fn restores_the_original_lockfile_after_simulation() {
        let db = IocDatabase::default();
        let dir = tempfile::tempdir().unwrap();
        let original = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/safe-pkg":{"version":"1.0.0"}}}"#;
        std::fs::write(dir.path().join("package-lock.json"), original).unwrap();
        let semaphore = Semaphore::new(1);

        run_simulation(
            &project(dir.path().to_path_buf()),
            &db,
            &semaphore,
            NO_TIMEOUT,
            |root| async move {
                std::fs::write(
                    root.join("package-lock.json"),
                    r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/other-pkg":{"version":"2.0.0"}}}"#,
                )
                .unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();

        let restored = std::fs::read_to_string(dir.path().join("package-lock.json")).unwrap();
        assert_eq!(restored, original);
        assert!(!dir.path().join("package-lock.json.orig").exists());
    }

    #[tokio::test]
    async fn restores_original_state_even_when_the_command_fails() {
        let db = IocDatabase::default();
        let dir = tempfile::tempdir().unwrap();
        let original = r#"{"lockfileVersion":3,"packages":{}}"#;
        std::fs::write(dir.path().join("package-lock.json"), original).unwrap();
        let semaphore = Semaphore::new(1);

        let result = run_simulation(
            &project(dir.path().to_path_buf()),
            &db,
            &semaphore,
            NO_TIMEOUT,
            |_root| async move { Err(std::io::Error::other("npm not found")) },
        )
        .await;

        assert!(result.is_err());
        let restored = std::fs::read_to_string(dir.path().join("package-lock.json")).unwrap();
        assert_eq!(restored, original);
    }

    #[tokio::test]
    async fn restores_an_existing_yarn_lock_mutated_by_the_command() {
        // Reproduit un comportement réel observé : `npm install` peut réécrire un
        // yarn.lock déjà présent en effet de bord, même en --package-lock-only.
        let db = IocDatabase::default();
        let dir = tempfile::tempdir().unwrap();
        let original_yarn_lock = "# yarn lockfile v1\noriginal-content\n";
        std::fs::write(dir.path().join("yarn.lock"), original_yarn_lock).unwrap();
        let semaphore = Semaphore::new(1);

        run_simulation(
            &project(dir.path().to_path_buf()),
            &db,
            &semaphore,
            NO_TIMEOUT,
            |root| async move {
                std::fs::write(root.join("yarn.lock"), "# mutated by npm\n").unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();

        let restored = std::fs::read_to_string(dir.path().join("yarn.lock")).unwrap();
        assert_eq!(restored, original_yarn_lock);
        assert!(!dir.path().join("yarn.lock.orig").exists());
    }

    #[tokio::test]
    async fn times_out_and_restores_state_when_the_command_hangs() {
        let db = IocDatabase::default();
        let dir = tempfile::tempdir().unwrap();
        let original = r#"{"lockfileVersion":3,"packages":{}}"#;
        std::fs::write(dir.path().join("package-lock.json"), original).unwrap();
        let semaphore = Semaphore::new(1);

        let result = run_simulation(
            &project(dir.path().to_path_buf()),
            &db,
            &semaphore,
            Duration::from_millis(50),
            |_root: PathBuf| std::future::pending::<std::io::Result<()>>(),
        )
        .await;

        assert!(result.is_err());
        let restored = std::fs::read_to_string(dir.path().join("package-lock.json")).unwrap();
        assert_eq!(restored, original);
    }
}

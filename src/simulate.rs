//! Simulation `npm install --package-lock-only` isolée pour évaluer les dépendances
//! qui seraient résolues aujourd'hui, sans modifier durablement le dépôt (SPEC-F04,
//! niveau 2). Le nombre de processus npm concurrents est borné par un sémaphore
//! (SPEC-T01) pour éviter de saturer le disque/les E/S, en particulier sous WSL.

use std::future::Future;
use std::path::PathBuf;

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

/// Simule `npm install` dans `project.root` et retourne les dépendances qui seraient
/// résolues aujourd'hui, vérifiées contre la base IOC. Le répertoire du projet est
/// restauré à l'identique une fois l'analyse terminée, y compris en cas d'échec npm.
pub async fn simulate_install(
    project: &Project,
    db: &IocDatabase,
    semaphore: &Semaphore,
) -> anyhow::Result<Vec<Finding>> {
    run_simulation(project, db, semaphore, run_npm_install).await
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

/// Cœur testable de la simulation : `command` est injecté pour permettre de tester
/// la logique de sauvegarde/restauration et d'analyse sans dépendre d'un vrai `npm`.
async fn run_simulation<F, Fut>(
    project: &Project,
    db: &IocDatabase,
    semaphore: &Semaphore,
    command: F,
) -> anyhow::Result<Vec<Finding>>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let lock_path = project.root.join("package-lock.json");
    let backup_path = project.root.join("package-lock.json.orig");

    let had_original = lock_path.exists();
    if had_original {
        tokio::fs::rename(&lock_path, &backup_path).await?;
    }

    let permit = semaphore.acquire().await?;
    let outcome = command(project.root.clone()).await;
    drop(permit);

    if let Err(ref err) = outcome {
        warn!(
            project = %project.root.display(),
            error = %err,
            "simulation npm install échouée"
        );
    }

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

    if had_original {
        tokio::fs::rename(&backup_path, &lock_path).await?;
    } else if lock_path.exists() {
        tokio::fs::remove_file(&lock_path).await?;
    }

    outcome?;
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let findings = run_simulation(&project(dir.path().to_path_buf()), &db, &semaphore, |root| async move {
            std::fs::write(
                root.join("package-lock.json"),
                r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/evil-pkg":{"version":"1.0.0"}}}"#,
            )
            .unwrap();
            Ok(())
        })
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

        run_simulation(&project(dir.path().to_path_buf()), &db, &semaphore, |root| async move {
            std::fs::write(
                root.join("package-lock.json"),
                r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/other-pkg":{"version":"2.0.0"}}}"#,
            )
            .unwrap();
            Ok(())
        })
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
            |_root| async move { Err(std::io::Error::other("npm not found")) },
        )
        .await;

        assert!(result.is_err());
        let restored = std::fs::read_to_string(dir.path().join("package-lock.json")).unwrap();
        assert_eq!(restored, original);
    }
}

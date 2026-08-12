//! Simulation `npm install --package-lock-only` isolée pour évaluer les dépendances
//! qui seraient résolues aujourd'hui (SPEC-F04, niveau 2). Exécutée dans une copie
//! isolée sous `working/`, **jamais** dans le répertoire du projet lui-même : constaté
//! en pratique, `npm install` peut réécrire un `yarn.lock` existant en effet de bord,
//! même en `--package-lock-only` — une stratégie de sauvegarde/restauration en place
//! reste intrinsèquement risquée. Le nombre de processus npm concurrents est borné
//! par un sémaphore (SPEC-T01) pour éviter de saturer le disque/les E/S.

use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

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

/// Nom du répertoire de travail créé dans le répertoire d'exécution courant au
/// démarrage (SPEC-F04) : accueille une copie isolée de chaque `package.json`
/// simulé — jamais le projet original.
pub const WORKING_DIRNAME: &str = "working";

/// Nom de commande npm par défaut, utilisé si `--npm-path` n'est pas fourni.
const DEFAULT_NPM_COMMAND: &str = "npm";

/// Résout la commande npm à utiliser : `npm_path` (`--npm-path`) s'il est fourni,
/// sinon `npm` recherché dans le PATH.
pub fn resolve_npm_command(npm_path: Option<&Path>) -> OsString {
    npm_path
        .map(|path| path.as_os_str().to_owned())
        .unwrap_or_else(|| OsString::from(DEFAULT_NPM_COMMAND))
}

/// Vérifie au démarrage que la commande npm résolue est utilisable, en tentant
/// `<npm> --version` (borné par un court timeout pour ne jamais bloquer le
/// démarrage). Toujours journalisé en `INFO`, succès ou échec (SPEC-F04) : si npm
/// est indisponible, la simulation d'installation (niveau 2) est entièrement
/// ignorée pour le scan — la vérification des `package-lock.json` générés ne peut
/// pas avoir lieu.
pub async fn check_npm_available(npm_command: &OsStr) -> bool {
    let probe = Command::new(npm_command).arg("--version").output();

    match tokio::time::timeout(Duration::from_secs(10), probe).await {
        Ok(Ok(output)) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            info!(
                npm = %npm_command.to_string_lossy(),
                version,
                "npm disponible : la simulation d'installation (SPEC-F04 niveau 2) sera exécutée"
            );
            true
        }
        Ok(Ok(output)) => {
            info!(
                npm = %npm_command.to_string_lossy(),
                status = %output.status,
                "npm indisponible (code de sortie non nul pour --version) : la vérification des package-lock.json générés ne pourra avoir lieu et sera ignorée"
            );
            false
        }
        Ok(Err(err)) => {
            info!(
                npm = %npm_command.to_string_lossy(),
                error = %err,
                "npm introuvable : la vérification des package-lock.json générés ne pourra avoir lieu et sera ignorée"
            );
            false
        }
        Err(_) => {
            info!(
                npm = %npm_command.to_string_lossy(),
                "npm --version n'a pas répondu à temps : la vérification des package-lock.json générés ne pourra avoir lieu et sera ignorée"
            );
            false
        }
    }
}

/// Sous-répertoire de travail dédié à un projet, nommé par le SHA1 du chemin de son
/// `package.json` (déterministe, sans collision entre projets).
fn sim_dir_for(working_dir: &Path, project_root: &Path) -> PathBuf {
    let package_json_path = project_root.join("package.json");
    let mut hasher = Sha1::new();
    hasher.update(package_json_path.to_string_lossy().as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    working_dir.join(hex)
}

/// Simule `npm install` pour `project` dans une copie isolée sous `working_dir` et
/// retourne les dépendances qui seraient résolues aujourd'hui, vérifiées contre la
/// base IOC. Le répertoire du projet original n'est à aucun moment ouvert en écriture.
/// `npm_command` est la commande résolue par [`resolve_npm_command`].
pub async fn simulate_install(
    project: &Project,
    db: &IocDatabase,
    semaphore: &Semaphore,
    working_dir: &Path,
    npm_timeout: Duration,
    npm_command: &OsStr,
) -> anyhow::Result<Vec<Finding>> {
    let sim_dir = sim_dir_for(working_dir, &project.root);
    let npm_command = npm_command.to_owned();
    run_simulation(
        project,
        db,
        semaphore,
        &sim_dir,
        npm_timeout,
        move |sim_dir| run_npm_install(sim_dir, npm_command),
    )
    .await
}

/// Lance `npm install` avec stdout/stderr capturés (jamais hérités du process
/// parent) : la sortie de npm ne doit jamais fuiter sur la console de
/// shai-hulud-guard, elle est journalisée en DEBUG pour le diagnostic (SPEC-T04).
async fn run_npm_install(sim_dir: PathBuf, npm_command: OsString) -> std::io::Result<()> {
    let output = Command::new(&npm_command)
        .args(NPM_ARGS)
        .current_dir(&sim_dir)
        .output()
        .await?;

    if !output.stdout.is_empty() {
        debug!(
            sim_dir = %sim_dir.display(),
            stdout = %String::from_utf8_lossy(&output.stdout),
            "sortie npm install"
        );
    }
    if !output.stderr.is_empty() {
        debug!(
            sim_dir = %sim_dir.display(),
            stderr = %String::from_utf8_lossy(&output.stderr),
            "sortie npm install"
        );
    }

    Ok(())
}

async fn cleanup(sim_dir: &Path) {
    if let Err(err) = tokio::fs::remove_dir_all(sim_dir).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            warn!(
                sim_dir = %sim_dir.display(),
                error = %err,
                "impossible de nettoyer le répertoire de travail"
            );
        }
    }
}

/// Cœur testable de la simulation : `command` est injecté pour permettre de tester
/// la logique de préparation/nettoyage et d'analyse sans dépendre d'un vrai `npm`.
async fn run_simulation<F, Fut>(
    project: &Project,
    db: &IocDatabase,
    semaphore: &Semaphore,
    sim_dir: &Path,
    npm_timeout: Duration,
    command: F,
) -> anyhow::Result<Vec<Finding>>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    // Repartir d'un état vierge à chaque simulation, indépendamment d'un éventuel
    // résidu laissé par un run précédent interrompu (même hash de projet).
    cleanup(sim_dir).await;
    tokio::fs::create_dir_all(sim_dir).await?;

    if let Err(err) = tokio::fs::copy(
        project.root.join("package.json"),
        sim_dir.join("package.json"),
    )
    .await
    {
        cleanup(sim_dir).await;
        return Err(err.into());
    }

    let permit = semaphore.acquire().await?;
    let outcome = match tokio::time::timeout(npm_timeout, command(sim_dir.to_path_buf())).await {
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

    let findings = if outcome.is_ok() {
        match tokio::fs::read_to_string(sim_dir.join("package-lock.json")).await {
            Ok(content) => parse_npm_lock(&content)
                .map(|deps| {
                    deps.iter()
                        .map(|dep| check_dependency(db, &project.root, &dep.name, &dep.version))
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    cleanup(sim_dir).await;

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

    #[test]
    fn resolve_npm_command_defaults_to_npm_in_path() {
        assert_eq!(resolve_npm_command(None), OsString::from("npm"));
    }

    #[test]
    fn resolve_npm_command_uses_the_explicit_path_when_given() {
        let path = Path::new("/usr/local/bin/npm");
        assert_eq!(resolve_npm_command(Some(path)), OsString::from(path));
    }

    #[tokio::test]
    async fn check_npm_available_returns_false_for_a_nonexistent_binary() {
        let available =
            check_npm_available(OsStr::new("this-binary-definitely-does-not-exist-xyz")).await;
        assert!(!available);
    }

    #[test]
    fn sim_dir_is_deterministic_and_distinct_per_project() {
        let working_dir = Path::new("/tmp/working");
        let a = sim_dir_for(working_dir, Path::new("/projects/a"));
        let b = sim_dir_for(working_dir, Path::new("/projects/b"));
        let a_again = sim_dir_for(working_dir, Path::new("/projects/a"));

        assert_eq!(a, a_again);
        assert_ne!(a, b);
        assert!(a.starts_with(working_dir));
    }

    #[tokio::test]
    async fn copies_only_package_json_and_analyzes_the_generated_lockfile() {
        let db = IocDatabase::from_csv("ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n").unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().join("package.json"),
            r#"{"name":"demo"}"#,
        )
        .unwrap();
        // Un yarn.lock d'origine ne doit jamais être touché ni même lu.
        std::fs::write(project_dir.path().join("yarn.lock"), "original yarn.lock\n").unwrap();

        let working_dir = tempfile::tempdir().unwrap();
        let sim_dir = sim_dir_for(working_dir.path(), project_dir.path());
        let semaphore = Semaphore::new(1);

        let findings = run_simulation(
            &project(project_dir.path().to_path_buf()),
            &db,
            &semaphore,
            &sim_dir,
            NO_TIMEOUT,
            |root| async move {
                // Le package.json du projet doit avoir été copié dans le sim_dir.
                assert_eq!(
                    std::fs::read_to_string(root.join("package.json")).unwrap(),
                    r#"{"name":"demo"}"#
                );
                assert!(!root.join("yarn.lock").exists());
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
        assert!(matches!(
            findings[0].status,
            crate::ioc::CompromiseStatus::Corrompue { .. }
        ));

        // Le projet original n'a jamais été modifié.
        assert_eq!(
            std::fs::read_to_string(project_dir.path().join("yarn.lock")).unwrap(),
            "original yarn.lock\n"
        );
        assert!(!project_dir.path().join("package-lock.json").exists());
        // Le répertoire de travail est nettoyé après la simulation.
        assert!(!sim_dir.exists());
    }

    #[tokio::test]
    async fn cleans_up_the_sim_dir_even_when_the_command_fails() {
        let db = IocDatabase::default();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().join("package.json"),
            r#"{"name":"demo"}"#,
        )
        .unwrap();
        let working_dir = tempfile::tempdir().unwrap();
        let sim_dir = sim_dir_for(working_dir.path(), project_dir.path());
        let semaphore = Semaphore::new(1);

        let result = run_simulation(
            &project(project_dir.path().to_path_buf()),
            &db,
            &semaphore,
            &sim_dir,
            NO_TIMEOUT,
            |_root| async move { Err(std::io::Error::other("npm not found")) },
        )
        .await;

        assert!(result.is_err());
        assert!(!sim_dir.exists());
    }

    #[tokio::test]
    async fn starts_fresh_even_if_a_previous_run_left_a_stale_sim_dir() {
        let db = IocDatabase::default();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().join("package.json"),
            r#"{"name":"demo"}"#,
        )
        .unwrap();
        let working_dir = tempfile::tempdir().unwrap();
        let sim_dir = sim_dir_for(working_dir.path(), project_dir.path());

        // Résidu d'un run précédent interrompu.
        std::fs::create_dir_all(&sim_dir).unwrap();
        std::fs::write(sim_dir.join("package-lock.json"), "stale content").unwrap();
        std::fs::write(sim_dir.join("package.json"), "stale package.json").unwrap();

        let semaphore = Semaphore::new(1);

        run_simulation(
            &project(project_dir.path().to_path_buf()),
            &db,
            &semaphore,
            &sim_dir,
            NO_TIMEOUT,
            |root| async move {
                assert_eq!(
                    std::fs::read_to_string(root.join("package.json")).unwrap(),
                    r#"{"name":"demo"}"#
                );
                Ok(())
            },
        )
        .await
        .unwrap();

        assert!(!sim_dir.exists());
    }

    #[tokio::test]
    async fn times_out_and_cleans_up_when_the_command_hangs() {
        let db = IocDatabase::default();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().join("package.json"),
            r#"{"name":"demo"}"#,
        )
        .unwrap();
        let working_dir = tempfile::tempdir().unwrap();
        let sim_dir = sim_dir_for(working_dir.path(), project_dir.path());
        let semaphore = Semaphore::new(1);

        let result = run_simulation(
            &project(project_dir.path().to_path_buf()),
            &db,
            &semaphore,
            &sim_dir,
            Duration::from_millis(50),
            |_root: PathBuf| std::future::pending::<std::io::Result<()>>(),
        )
        .await;

        assert!(result.is_err());
        assert!(!sim_dir.exists());
    }
}

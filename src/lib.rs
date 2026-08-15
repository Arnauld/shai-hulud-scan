pub mod audit;
pub mod cli;
pub mod comments;
pub mod discovery;
pub mod hunt;
pub mod ioc;
pub mod iocs;
pub mod lockfile;
pub mod progress;
pub mod registry;
pub mod report;
pub mod scan;
pub mod simulate;
pub mod walker;
pub mod workspace;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tracing::{debug, info};

use cli::Cli;
use ioc::IocDatabase;
use progress::DotProgress;
use report::Report;

/// Orchestre une passe d'audit complète sur `cli.path` et retourne le rapport final :
/// vérification de la disponibilité de npm (journalisée en INFO, `--npm-path` pour la
/// forcer), chargement de la base IOC réseau + fallback local (SPEC-F01), un unique
/// parcours du workspace combinant découverte de projets (SPEC-F03), scan passif
/// (SPEC-F05/F08) et repérage des dépôts `.git` (SPEC-F08) — plutôt que trois
/// parcours indépendants de la même arborescence, `workspace::walk_workspace` —
/// audit des lockfiles existants (SPEC-F04 niveau 1), simulation `npm install`
/// (SPEC-F04 niveau 2, dans une copie isolée sous `working/` — jamais dans le projet
/// original — entièrement ignorée si npm est indisponible, avec des processus
/// concurrents bornés par un sémaphore dimensionné par `cli.workers`, SPEC-T01) et
/// recherche active de signaux malveillants sur le disque (SPEC-F06/F07). Le parcours
/// de fichiers et la simulation npm affichent chacun un flux de points texte
/// (`progress::DotProgress`, plus robuste qu'une barre `indicatif` sur certains
/// terminaux Windows) — désactivables via `--no-color` (SPEC-T02).
pub async fn run(cli: Cli) -> anyhow::Result<Report> {
    let npm_command = simulate::resolve_npm_command(cli.npm_path.as_deref());
    let npm_available = simulate::check_npm_available(&npm_command).await;

    let working_dir = std::env::current_dir()?.join(simulate::WORKING_DIRNAME);
    if npm_available {
        tokio::fs::create_dir_all(&working_dir).await?;
    }

    let iocs_config = iocs::load(cli.iocs_file.as_deref())?;
    let db = IocDatabase::load(
        cli.database.as_deref(),
        cli.offline,
        &iocs_config.official_ioc_url,
    )
    .await?;

    info!(path = %cli.path.display(), "lancement de l'analyse");
    let walk_progress = DotProgress::new(true, 10, 100);
    let workspace = workspace::walk_workspace(
        &cli.path,
        &walk_progress,
        cli.no_ignore,
        &iocs_config,
        cli.walk_threads,
    );
    walk_progress.finish();
    // Le compte de fichiers ("nombre de fichier à analyser", SPEC-T04) n'est connu
    // qu'une fois le parcours terminé : il est affiché à la suite des points de
    // progression, pas besoin d'un log INFO séparé, c'est déjà une information
    // console visible (silencieuse elle aussi via --no-color, comme le reste).
    if !cli.no_color {
        eprintln!(
            "{} fichier(s) analysé(s), {} projet(s) découvert(s)",
            walk_progress.position(),
            workspace.projects.len()
        );
    }
    let projects = workspace.projects;
    let install_command_mentions = workspace.install_command_mentions;

    info!("Analyse - phase audit projects");
    let mut findings: Vec<_> = projects
        .iter()
        .flat_map(|project| {
            let mut project_findings = audit::audit_project(&db, project);
            project_findings.extend(audit::audit_installed_packages(
                &db,
                project,
                cli.walk_threads,
            ));
            project_findings
        })
        .collect();

    info!("Analyse - phase hunting install scripts");
    let mut threats = hunt::hunt(&cli.path, &projects, &iocs_config, &workspace.git_dirs);
    let install_scripts: Vec<_> = projects
        .iter()
        .flat_map(|project| hunt::inventory_install_scripts(&project.root))
        .collect();
    threats.extend(workspace.threat_signals);
    threats.extend(
        projects
            .iter()
            .flat_map(|project| registry::scan_project(project, &iocs_config)),
    );
    threats.extend(projects.iter().flat_map(audit::audit_lockfile_drift));

    info!("Analyse - npm install simulation");
    let project_count = projects.len();
    let db = Arc::new(db);
    let semaphore = Arc::new(Semaphore::new(cli.workers.max(1)));
    let npm_timeout = Duration::from_secs(cli.npm_timeout);
    let simulation_progress = DotProgress::new(true, 1, 100);

    if npm_available {
        let mut simulations = tokio::task::JoinSet::new();
        for project in projects {
            let db = Arc::clone(&db);
            let semaphore = Arc::clone(&semaphore);
            let working_dir = working_dir.clone();
            let npm_command = npm_command.clone();
            simulations.spawn(async move {
                simulate::simulate_install(
                    &project,
                    &db,
                    &semaphore,
                    &working_dir,
                    npm_timeout,
                    &npm_command,
                )
                .await
            });
        }

        while let Some(outcome) = simulations.join_next().await {
            simulation_progress.inc();
            if let Ok(Ok(simulated)) = outcome {
                findings.extend(simulated);
            }
        }
    } else {
        debug!("simulation npm install ignorée pour l'ensemble du scan (npm indisponible)");
    }
    simulation_progress.finish();
    if !cli.no_color && npm_available {
        eprintln!(
            "{} simulation(s) npm install effectuée(s)",
            simulation_progress.position()
        );
    }

    // DEBUG (pas INFO) : le rapport lui-même (stdout / --report-file / --json) est
    // déjà la restitution visible du résultat, inutile de la dupliquer en console.
    debug!(
        findings = findings.len(),
        threats = threats.len(),
        "rapport généré"
    );
    Ok(Report::from_findings(&findings)
        .with_threats(threats)
        .with_install_scripts(install_scripts)
        .with_install_command_mentions(install_command_mentions)
        .with_project_count(project_count))
}

pub mod audit;
pub mod cli;
pub mod discovery;
pub mod hunt;
pub mod ioc;
pub mod lockfile;
pub mod report;
pub mod scan;
pub mod simulate;
pub mod walker;

use std::sync::Arc;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use cli::Cli;
use discovery::discover;
use ioc::IocDatabase;
use report::Report;

/// Orchestre une passe d'audit complète sur `cli.path` et retourne le rapport final :
/// vérification de la disponibilité de npm (journalisée en INFO, `--npm-path` pour la
/// forcer), chargement de la base IOC réseau + fallback local (SPEC-F01), audit des
/// lockfiles existants (SPEC-F04 niveau 1), simulation `npm install` (SPEC-F04
/// niveau 2, dans une copie isolée sous `working/` — jamais dans le projet original —
/// entièrement ignorée si npm est indisponible, avec des processus concurrents
/// bornés par un sémaphore dimensionné par `cli.workers`, SPEC-T01) et recherche
/// active de signaux malveillants sur le disque (SPEC-F06/F07). Le parcours de
/// fichiers et la simulation npm affichent une barre de progression `indicatif`,
/// désactivable via `--no-color` (SPEC-T02).
pub async fn run(cli: Cli) -> anyhow::Result<Report> {
    let npm_command = simulate::resolve_npm_command(cli.npm_path.as_deref());
    let npm_available = simulate::check_npm_available(&npm_command).await;

    let working_dir = std::env::current_dir()?.join(simulate::WORKING_DIRNAME);
    if npm_available {
        tokio::fs::create_dir_all(&working_dir).await?;
    }

    let db = IocDatabase::load(cli.database.as_deref(), cli.offline).await?;

    info!(path = %cli.path.display(), "lancement de l'analyse");
    let walk_progress = spinner(cli.no_color)?;
    let projects = discover(&cli.path, &walk_progress);
    // Le compte de fichiers ("nombre de fichier à analyser", SPEC-T04) n'est connu
    // qu'une fois le parcours terminé : il est affiché progressivement dans le
    // spinner puis figé ici sur la même ligne — pas besoin d'un log INFO séparé,
    // c'est déjà une information console visible.
    walk_progress.finish_with_message(format!(
        "{} fichier(s) analysé(s), {} projet(s) découvert(s)",
        walk_progress.position(),
        projects.len()
    ));

    let mut findings: Vec<_> = projects
        .iter()
        .flat_map(|project| {
            let mut project_findings = audit::audit_project(&db, project);
            project_findings.extend(audit::audit_installed_packages(&db, project));
            project_findings
        })
        .collect();

    let mut threats = hunt::hunt(&cli.path, &projects);
    let install_scripts: Vec<_> = projects
        .iter()
        .flat_map(|project| hunt::inventory_install_scripts(&project.root))
        .collect();
    let (c2_signals, install_command_mentions) = scan::scan_workspace(&cli.path);
    threats.extend(c2_signals);

    let project_count = projects.len();
    let db = Arc::new(db);
    let semaphore = Arc::new(Semaphore::new(cli.workers.max(1)));
    let npm_timeout = Duration::from_secs(cli.npm_timeout);
    let simulation_progress = bar(
        cli.no_color,
        if npm_available {
            project_count as u64
        } else {
            0
        },
    )?;

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
            simulation_progress.inc(1);
            if let Ok(Ok(simulated)) = outcome {
                findings.extend(simulated);
            }
        }
    } else {
        debug!("simulation npm install ignorée pour l'ensemble du scan (npm indisponible)");
    }
    simulation_progress.finish_and_clear();

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

/// Barre indéterminée pour le parcours de fichiers (SPEC-T02).
fn spinner(no_color: bool) -> anyhow::Result<ProgressBar> {
    if no_color {
        return Ok(ProgressBar::hidden());
    }
    let progress = ProgressBar::new_spinner();
    progress.set_style(ProgressStyle::with_template(
        "{spinner:.cyan} {msg} ({pos} entrées)",
    )?);
    progress.set_message("Parcours des fichiers…");
    progress.enable_steady_tick(Duration::from_millis(120));
    Ok(progress)
}

/// Barre déterminée (longueur connue à l'avance) pour la simulation npm (SPEC-T02).
fn bar(no_color: bool, len: u64) -> anyhow::Result<ProgressBar> {
    if no_color {
        return Ok(ProgressBar::hidden());
    }
    let progress = ProgressBar::new(len);
    progress.set_style(ProgressStyle::with_template(
        "{bar:40.cyan/blue} {pos}/{len} simulation(s) npm install",
    )?);
    Ok(progress)
}

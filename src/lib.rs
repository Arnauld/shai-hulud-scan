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

use cli::Cli;
use discovery::discover;
use ioc::IocDatabase;
use report::Report;

/// Orchestre une passe d'audit complète sur `cli.path` et retourne le rapport final :
/// chargement de la base IOC réseau + fallback local (SPEC-F01), audit des lockfiles
/// existants (SPEC-F04 niveau 1), simulation `npm install` (SPEC-F04 niveau 2,
/// processus concurrents bornés par un sémaphore dimensionné par `cli.workers`,
/// SPEC-T01) et recherche active de signaux malveillants sur le disque (SPEC-F06/F07).
/// Le parcours de fichiers et la simulation npm affichent une barre de progression
/// `indicatif`, désactivable via `--no-color` (SPEC-T02).
pub async fn run(cli: Cli) -> anyhow::Result<Report> {
    let db = IocDatabase::load(cli.database.as_deref(), cli.offline).await?;

    let walk_progress = spinner(cli.no_color)?;
    let projects = discover(&cli.path, &walk_progress);
    walk_progress.finish_with_message(format!("{} projet(s) découvert(s)", projects.len()));

    let mut findings: Vec<_> = projects
        .iter()
        .flat_map(|project| {
            let mut project_findings = audit::audit_project(&db, project);
            project_findings.extend(audit::audit_installed_packages(&db, project));
            project_findings
        })
        .collect();

    let threats = hunt::hunt(&cli.path, &projects);

    let db = Arc::new(db);
    let semaphore = Arc::new(Semaphore::new(cli.workers.max(1)));
    let simulation_progress = bar(cli.no_color, projects.len() as u64)?;
    let mut simulations = tokio::task::JoinSet::new();
    for project in projects {
        let db = Arc::clone(&db);
        let semaphore = Arc::clone(&semaphore);
        simulations
            .spawn(async move { simulate::simulate_install(&project, &db, &semaphore).await });
    }

    while let Some(outcome) = simulations.join_next().await {
        simulation_progress.inc(1);
        if let Ok(Ok(simulated)) = outcome {
            findings.extend(simulated);
        }
    }
    simulation_progress.finish_and_clear();

    Ok(Report::from_findings(&findings).with_threats(threats))
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

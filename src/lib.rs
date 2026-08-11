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
pub async fn run(cli: Cli) -> anyhow::Result<Report> {
    let db = IocDatabase::load(cli.database.as_deref(), cli.offline).await?;

    let projects = discover(&cli.path);

    let mut findings: Vec<_> = projects
        .iter()
        .flat_map(|project| audit::audit_project(&db, project))
        .collect();

    let threats = hunt::hunt(&cli.path, &projects);

    let db = Arc::new(db);
    let semaphore = Arc::new(Semaphore::new(cli.workers.max(1)));
    let mut simulations = tokio::task::JoinSet::new();
    for project in projects {
        let db = Arc::clone(&db);
        let semaphore = Arc::clone(&semaphore);
        simulations
            .spawn(async move { simulate::simulate_install(&project, &db, &semaphore).await });
    }

    while let Some(outcome) = simulations.join_next().await {
        if let Ok(Ok(simulated)) = outcome {
            findings.extend(simulated);
        }
    }

    Ok(Report::from_findings(&findings).with_threats(threats))
}

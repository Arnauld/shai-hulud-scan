pub mod audit;
pub mod cli;
pub mod discovery;
pub mod hunt;
pub mod ioc;
pub mod report;
pub mod scan;
pub mod walker;

use cli::Cli;
use discovery::discover;
use ioc::IocDatabase;
use report::Report;

/// Orchestre une passe d'audit complète sur `cli.path` et retourne le rapport final.
///
/// Le chargement réseau de la base IOC (SPEC-F01), la simulation `npm install`
/// (SPEC-F04 niveau 2) et le Threat Hunting (SPEC-F06/F07) restent à brancher ici.
pub fn run(cli: Cli) -> anyhow::Result<Report> {
    let db = match &cli.database {
        Some(path) => {
            let csv = std::fs::read_to_string(path)?;
            IocDatabase::from_csv(&csv)?
        }
        None => IocDatabase::default(),
    };

    let projects = discover(&cli.path);
    let findings: Vec<_> = projects
        .iter()
        .flat_map(|project| audit::audit_project(&db, project))
        .collect();

    Ok(Report::from_findings(&findings))
}

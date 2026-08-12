use clap::Parser;
use shai_hulud_guard::cli::Cli;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json_output = cli.json;
    let report_file = cli.report_file.clone();
    if cli.no_color {
        console::set_colors_enabled(false);
    }
    init_logging(cli.verbose, cli.no_color);

    let report = shai_hulud_guard::run(cli).await?;

    if json_output {
        println!("{}", report.to_json()?);
    } else {
        print!("{}", report.render_text());
    }

    if let Some(path) = report_file {
        let plain_report = console::strip_ansi_codes(&report.render_text()).to_string();
        std::fs::write(path, plain_report)?;
    }

    Ok(())
}

/// Initialise la journalisation `tracing` sur stderr (SPEC-T04). `--verbose` fixe le
/// niveau par défaut à DEBUG pour `shai_hulud_guard` uniquement (INFO sinon, et pour
/// les dépendances dans tous les cas, afin d'éviter le bruit interne de crates comme
/// `ignore`) ; `RUST_LOG` prime sur ce flag si défini.
fn init_logging(verbose: bool, no_color: bool) {
    let default_directive = if verbose {
        "info,shai_hulud_guard=debug"
    } else {
        "info"
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(!no_color)
        .with_env_filter(filter)
        .init();
}

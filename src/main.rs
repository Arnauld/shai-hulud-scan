use std::path::Path;

use anyhow::Context;
use clap::Parser;
use shai_hulud_guard::cli::Cli;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

const DEFAULT_FILE_DIRECTIVE: &str = "info,shai_hulud_guard=debug";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json_output = cli.json;
    let report_file = cli.report_file.clone();
    let report_level = cli.report_level;
    if cli.no_color {
        console::set_colors_enabled(false);
    }
    init_logging(
        cli.verbose,
        cli.no_color,
        cli.log_file.as_deref(),
        cli.log_console_directive.as_deref(),
        cli.log_file_directive.as_deref(),
    )?;

    let report = shai_hulud_guard::run(cli).await?;

    if json_output {
        println!("{}", report.to_json()?);
    } else {
        print!("{}", report.render_text(report_level));
    }

    if let Some(path) = report_file {
        let plain_report = console::strip_ansi_codes(&report.render_text(report_level)).to_string();
        std::fs::write(path, plain_report)?;
    }

    Ok(())
}

/// Initialise la journalisation `tracing` (SPEC-T04) :
/// - **stderr** : toujours actif. Priorité de la directive de filtrage : `RUST_LOG`
///   (variable d'environnement) > `--log-console-directive` (explicite) > `--verbose`
///   (DEBUG pour `shai_hulud_guard` uniquement si activé, INFO sinon — et pour les
///   dépendances dans tous les cas, afin d'éviter le bruit interne de crates comme
///   `ignore`).
/// - **`--log-file <path>`** : en plus de stderr (jamais à sa place), pour permettre
///   de suivre un scan en cours avec `tail -f` sans attendre la fin (le rapport
///   final, lui, n'est écrit qu'une fois le scan terminé). Toujours au niveau DEBUG
///   par défaut, indépendamment de `--verbose` et de `RUST_LOG` — remplaçable via
///   `--log-file-directive`.
fn init_logging(
    verbose: bool,
    no_color: bool,
    log_file: Option<&Path>,
    log_console_directive: Option<&str>,
    log_file_directive: Option<&str>,
) -> anyhow::Result<()> {
    let default_console_directive = if verbose {
        "info,shai_hulud_guard=debug"
    } else {
        "info"
    };
    let console_directive = log_console_directive.unwrap_or(default_console_directive);
    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(console_directive));
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(!no_color)
        .with_filter(console_filter);

    let registry = tracing_subscriber::registry().with(stderr_layer);

    match log_file {
        Some(path) => {
            let dir = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            let filename = path
                .file_name()
                .context("--log-file doit pointer vers un fichier, pas un dossier")?;
            let file_appender = tracing_appender::rolling::never(dir, filename);
            let file_directive = log_file_directive.unwrap_or(DEFAULT_FILE_DIRECTIVE);
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(file_appender)
                .with_ansi(false)
                .with_filter(EnvFilter::new(file_directive));
            registry.with(file_layer).init();
        }
        None => registry.init(),
    }

    Ok(())
}

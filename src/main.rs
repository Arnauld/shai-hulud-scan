use clap::Parser;
use shai_hulud_guard::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json_output = cli.json;
    let report_file = cli.report_file.clone();
    if cli.no_color {
        console::set_colors_enabled(false);
    }

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

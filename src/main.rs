use clap::Parser;
use shai_hulud_guard::cli::Cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json_output = cli.json;
    let report_file = cli.report_file.clone();

    let report = shai_hulud_guard::run(cli)?;

    if json_output {
        println!("{}", report.to_json()?);
    } else {
        println!("{} dépendance(s) analysée(s).", report.findings.len());
        for finding in &report.findings {
            if finding.vulnerable {
                println!("[VULNÉRABLE] {}@{}", finding.package, finding.version);
            }
        }
    }

    if let Some(path) = report_file {
        std::fs::write(path, report.to_json()?)?;
    }

    Ok(())
}

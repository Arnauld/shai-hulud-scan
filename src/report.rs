//! Formats de restitution : console ANSI, fichier rapport, JSON structuré (SPEC-T02),
//! niveau de verbosité du rapport (SPEC-T05).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use console::style;
use serde::Serialize;

use crate::audit::Finding;
use crate::hunt::{InstallScript, ThreatSignal};
use crate::ioc::CompromiseStatus;

/// Niveau de détail du rapport (`--report-level`), indépendant du niveau de log
/// `--verbose` (SPEC-T04) : réutilise la même échelle `ERROR < WARN < INFO < DEBUG`
/// (SPEC-T05). Cumulatif : chaque niveau inclut le contenu des niveaux précédents.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ReportLevel {
    /// Uniquement le récapitulatif des dépendances `CORROMPU`/`VULNÉRABLE` et les
    /// menaces détectées.
    Error,
    /// + le nombre total de dépendances analysées.
    Warn,
    /// + le nombre de projets npm/yarn analysés.
    Info,
    /// + la liste complète des dépendances `SAIN` (verbose, valeur par défaut).
    #[default]
    Debug,
}

/// Rapport d'audit sérialisable, indépendant du format de sortie final.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub project_count: usize,
    pub findings: Vec<FindingReport>,
    pub threats: Vec<ThreatSignal>,
    /// Inventaire des scripts `preinstall`/`postinstall` rencontrés (SPEC-F08) — pas
    /// des menaces en soi, juste une liste pour inspection manuelle.
    pub install_scripts: Vec<InstallScript>,
}

#[derive(Debug, Serialize)]
pub struct FindingReport {
    pub project: PathBuf,
    pub package: String,
    pub version: String,
    pub status: CompromiseStatus,
}

impl From<&Finding> for FindingReport {
    fn from(finding: &Finding) -> Self {
        Self {
            project: finding.project.clone(),
            package: finding.package.clone(),
            version: finding.version.clone(),
            status: finding.status.clone(),
        }
    }
}

/// Rang de sévérité utilisé pour trier le récapitulatif au sein d'un même projet :
/// `Corrompue` (confirmé) avant `Vulnerable` (à surveiller).
fn severity_rank(status: &CompromiseStatus) -> u8 {
    match status {
        CompromiseStatus::Corrompue { .. } => 0,
        CompromiseStatus::Vulnerable { .. } => 1,
        CompromiseStatus::Sain => 2,
    }
}

impl Report {
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self {
            project_count: 0,
            findings: findings.iter().map(FindingReport::from).collect(),
            threats: Vec::new(),
            install_scripts: Vec::new(),
        }
    }

    /// Attache les signaux de Threat Hunting (SPEC-F06/F07) au rapport.
    pub fn with_threats(mut self, threats: Vec<ThreatSignal>) -> Self {
        self.threats = threats;
        self
    }

    /// Attache l'inventaire des scripts `preinstall`/`postinstall` (SPEC-F08),
    /// affiché uniquement au niveau `Debug` du rapport.
    pub fn with_install_scripts(mut self, install_scripts: Vec<InstallScript>) -> Self {
        self.install_scripts = install_scripts;
        self
    }

    /// Attache le nombre de projets npm/yarn analysés (affiché à partir du niveau
    /// `Info`, SPEC-T05).
    pub fn with_project_count(mut self, project_count: usize) -> Self {
        self.project_count = project_count;
        self
    }

    /// Sérialise le rapport en JSON structuré (option `--json`, SPEC-T02). Toujours
    /// complet, indépendamment de `--report-level` (SPEC-T05) : destiné à
    /// l'intégration programmatique, il ne doit jamais perdre d'information. Chaque
    /// dépendance y porte déjà son projet d'origine (`FindingReport::project`).
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Rend le rapport en texte lisible pour la console, filtré selon `level`
    /// (SPEC-T05). Coloré via codes ANSI selon `console::colors_enabled()`
    /// (auto-détection TTY, ou forcé par `--no-color` / `console::set_colors_enabled`)
    /// — utiliser `console::strip_ansi_codes` sur le résultat pour obtenir la version
    /// "texte brut" du rapport-fichier (SPEC-T02), lui aussi filtré par `level`.
    pub fn render_text(&self, level: ReportLevel) -> String {
        let mut out = String::new();

        if level >= ReportLevel::Warn {
            out.push_str(&format!(
                "{} dépendance(s) analysée(s).\n",
                style(self.findings.len()).bold()
            ));
        }
        if level >= ReportLevel::Info {
            out.push_str(&format!(
                "{} projet(s) npm/yarn analysé(s).\n",
                style(self.project_count).bold()
            ));
        }

        // CORROMPU et VULNÉRABLE sont toujours affichés, quel que soit le niveau,
        // regroupés par projet (SPEC-T05) : ce sont les deux verdicts anormaux
        // (SPEC-F04), avec une sévérité distincte.
        let anomalies: Vec<&FindingReport> = self
            .findings
            .iter()
            .filter(|f| f.status != CompromiseStatus::Sain)
            .collect();

        if !anomalies.is_empty() {
            let mut by_project: BTreeMap<&Path, Vec<&FindingReport>> = BTreeMap::new();
            for finding in &anomalies {
                by_project
                    .entry(finding.project.as_path())
                    .or_default()
                    .push(finding);
            }

            out.push_str(&format!(
                "\n{}\n",
                style("Récapitulatif des dépendances problématiques par projet :").bold()
            ));
            for (project, mut findings) in by_project {
                findings.sort_by(|a, b| {
                    severity_rank(&a.status)
                        .cmp(&severity_rank(&b.status))
                        .then_with(|| a.package.cmp(&b.package))
                });

                out.push_str(&format!("\n{}\n", style(project.display()).bold()));
                for finding in findings {
                    match &finding.status {
                        CompromiseStatus::Corrompue { .. } => {
                            out.push_str(&format!(
                                "  {} {}@{}\n",
                                style("[CORROMPU]").red().bold(),
                                finding.package,
                                finding.version
                            ));
                        }
                        CompromiseStatus::Vulnerable {
                            known_compromised_versions,
                            ..
                        } => {
                            out.push_str(&format!(
                                "  {} {}@{} (versions compromises connues : {})\n",
                                style("[VULNÉRABLE]").yellow().bold(),
                                finding.package,
                                finding.version,
                                known_compromised_versions.join(", ")
                            ));
                        }
                        CompromiseStatus::Sain => unreachable!("filtré ci-dessus"),
                    }
                }
            }
        }

        for threat in &self.threats {
            out.push_str(&format!(
                "{} {:?} : {} ({})\n",
                style("[MENACE]").yellow().bold(),
                threat.category,
                threat.path.display(),
                threat.detail
            ));
        }

        if level >= ReportLevel::Debug {
            for finding in &self.findings {
                if finding.status == CompromiseStatus::Sain {
                    out.push_str(&format!(
                        "{} {}@{}\n",
                        style("[SAIN]").green(),
                        finding.package,
                        finding.version
                    ));
                }
            }

            if !self.install_scripts.is_empty() {
                out.push_str(&format!(
                    "\n{}\n",
                    style("Scripts preinstall/postinstall trouvés (à inspecter) :").bold()
                ));
                for script in &self.install_scripts {
                    out.push_str(&format!(
                        "  {} {:?} : {} ({})\n",
                        style("[SCRIPT]").cyan(),
                        script.hook,
                        script.command,
                        script.package_json.display()
                    ));
                }
            }
        }

        if anomalies.is_empty() && self.threats.is_empty() {
            out.push_str(&format!(
                "{}\n",
                style("Aucune compromission détectée.").green()
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corrompue(version: &str) -> CompromiseStatus {
        CompromiseStatus::Corrompue {
            version: version.to_string(),
        }
    }

    fn vulnerable(version: &str, known_compromised_versions: &[&str]) -> CompromiseStatus {
        CompromiseStatus::Vulnerable {
            version: version.to_string(),
            known_compromised_versions: known_compromised_versions
                .iter()
                .map(|v| v.to_string())
                .collect(),
        }
    }

    fn finding(project: &str, package: &str, version: &str, status: CompromiseStatus) -> Finding {
        Finding {
            project: PathBuf::from(project),
            package: package.to_string(),
            version: version.to_string(),
            status,
        }
    }

    #[test]
    fn serializes_findings_to_json() {
        let findings = vec![finding("/proj", "evil-pkg", "1.0.0", corrompue("1.0.0"))];
        let report = Report::from_findings(&findings);
        let json = report.to_json().unwrap();
        assert!(json.contains("\"Corrompue\""));
        assert!(json.contains("\"1.0.0\""));
        assert!(json.contains("\"project\""));
    }

    #[test]
    fn renders_readable_text_report() {
        let findings = vec![finding("/proj", "evil-pkg", "1.0.0", corrompue("1.0.0"))];
        let threats = vec![crate::hunt::ThreatSignal {
            category: crate::hunt::ThreatCategory::SuspiciousFile,
            path: std::path::PathBuf::from("/tmp/setup.mjs"),
            detail: "fichier suspect connu".to_string(),
        }];
        let report = Report::from_findings(&findings).with_threats(threats);
        let text = report.render_text(ReportLevel::Debug);

        assert!(text.contains("evil-pkg@1.0.0"));
        assert!(text.contains("SuspiciousFile"));
        assert!(text.contains("setup.mjs"));
    }

    #[test]
    fn renders_vulnerable_findings_with_known_compromised_versions() {
        let findings = vec![finding(
            "/proj",
            "evil-pkg",
            "2.0.0",
            vulnerable("2.0.0", &["1.0.0", "1.1.0"]),
        )];
        let report = Report::from_findings(&findings);
        let text = report.render_text(ReportLevel::Error);

        assert!(text.contains("[VULNÉRABLE]"));
        assert!(text.contains("evil-pkg@2.0.0"));
        assert!(text.contains("1.0.0, 1.1.0"));
    }

    #[test]
    fn groups_the_recap_by_project_in_sorted_order() {
        let findings = vec![
            finding("/projects/b-proj", "evil-pkg", "1.0.0", corrompue("1.0.0")),
            finding(
                "/projects/a-proj",
                "other-pkg",
                "2.0.0",
                vulnerable("2.0.0", &["1.0.0"]),
            ),
            finding("/projects/a-proj", "evil-pkg", "1.0.0", corrompue("1.0.0")),
        ];
        let report = Report::from_findings(&findings);
        let text = report.render_text(ReportLevel::Error);

        let a_proj_pos = text.find("/projects/a-proj").unwrap();
        let b_proj_pos = text.find("/projects/b-proj").unwrap();
        assert!(
            a_proj_pos < b_proj_pos,
            "les projets doivent être triés par chemin : {text}"
        );

        // Au sein de /projects/a-proj : Corrompue (evil-pkg) avant Vulnerable (other-pkg).
        let evil_pos = text.find("evil-pkg@1.0.0").unwrap();
        let other_pos = text.find("other-pkg@2.0.0").unwrap();
        assert!(evil_pos < other_pos);
        assert!(evil_pos > a_proj_pos && evil_pos < b_proj_pos);
    }

    #[test]
    fn stripping_ansi_codes_yields_the_same_plain_content() {
        console::set_colors_enabled(true);

        let findings = vec![finding("/proj", "evil-pkg", "1.0.0", corrompue("1.0.0"))];
        let report = Report::from_findings(&findings);
        let colored = report.render_text(ReportLevel::Debug);
        let plain = console::strip_ansi_codes(&colored).to_string();

        assert!(colored.contains('\u{1b}'));
        assert!(!plain.contains('\u{1b}'));
        assert!(plain.contains("evil-pkg@1.0.0"));
    }

    #[test]
    fn report_level_controls_how_much_detail_is_shown() {
        let findings = vec![
            finding("/proj", "evil-pkg", "1.0.0", corrompue("1.0.0")),
            finding("/proj", "safe-pkg", "2.0.0", CompromiseStatus::Sain),
        ];
        let report = Report::from_findings(&findings).with_project_count(3);

        let error_text = report.render_text(ReportLevel::Error);
        assert!(error_text.contains("evil-pkg@1.0.0"));
        assert!(!error_text.contains("dépendance(s) analysée(s)"));
        assert!(!error_text.contains("projet(s)"));
        assert!(!error_text.contains("safe-pkg"));

        let warn_text = report.render_text(ReportLevel::Warn);
        assert!(warn_text.contains("dépendance(s) analysée(s)"));
        assert!(!warn_text.contains("projet(s) npm/yarn analysé"));
        assert!(!warn_text.contains("safe-pkg"));

        let info_text = report.render_text(ReportLevel::Info);
        assert!(info_text.contains("3"));
        assert!(info_text.contains("projet(s) npm/yarn analysé"));
        assert!(!info_text.contains("safe-pkg"));

        let debug_text = report.render_text(ReportLevel::Debug);
        assert!(debug_text.contains("safe-pkg@2.0.0"));
    }

    #[test]
    fn default_report_level_is_debug() {
        assert_eq!(ReportLevel::default(), ReportLevel::Debug);
    }

    #[test]
    fn install_scripts_are_shown_only_at_debug_level() {
        let report = Report::from_findings(&[]).with_install_scripts(vec![InstallScript {
            package_json: PathBuf::from("/proj/package.json"),
            hook: crate::hunt::InstallHook::Preinstall,
            command: "node build.js".to_string(),
        }]);

        let error_text = report.render_text(ReportLevel::Error);
        assert!(!error_text.contains("node build.js"));

        let debug_text = report.render_text(ReportLevel::Debug);
        assert!(debug_text.contains("node build.js"));
        assert!(debug_text.contains("[SCRIPT]"));
    }
}

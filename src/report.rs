//! Formats de restitution : console ANSI, fichier rapport, JSON structuré (SPEC-T02),
//! niveau de verbosité du rapport (SPEC-T05).

use console::style;
use serde::Serialize;

use crate::audit::{Finding, Status};
use crate::hunt::ThreatSignal;

/// Niveau de détail du rapport (`--report-level`), indépendant du niveau de log
/// `--verbose` (SPEC-T04) : réutilise la même échelle `ERROR < WARN < INFO < DEBUG`
/// (SPEC-T05). Cumulatif : chaque niveau inclut le contenu des niveaux précédents.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ReportLevel {
    /// Uniquement les dépendances `VULNÉRABLE` et les menaces détectées.
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
}

#[derive(Debug, Serialize)]
pub struct FindingReport {
    pub package: String,
    pub version: String,
    pub vulnerable: bool,
}

impl From<&Finding> for FindingReport {
    fn from(finding: &Finding) -> Self {
        Self {
            package: finding.package.clone(),
            version: finding.version.clone(),
            vulnerable: finding.status == Status::Vulnerable,
        }
    }
}

impl Report {
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self {
            project_count: 0,
            findings: findings.iter().map(FindingReport::from).collect(),
            threats: Vec::new(),
        }
    }

    /// Attache les signaux de Threat Hunting (SPEC-F06/F07) au rapport.
    pub fn with_threats(mut self, threats: Vec<ThreatSignal>) -> Self {
        self.threats = threats;
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
    /// l'intégration programmatique, il ne doit jamais perdre d'information.
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

        let vulnerable_count = self.findings.iter().filter(|f| f.vulnerable).count();
        for finding in self.findings.iter().filter(|f| f.vulnerable) {
            out.push_str(&format!(
                "{} {}@{}\n",
                style("[VULNÉRABLE]").red().bold(),
                finding.package,
                finding.version
            ));
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
            for finding in self.findings.iter().filter(|f| !f.vulnerable) {
                out.push_str(&format!(
                    "{} {}@{}\n",
                    style("[SAIN]").green(),
                    finding.package,
                    finding.version
                ));
            }
        }

        if vulnerable_count == 0 && self.threats.is_empty() {
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

    #[test]
    fn serializes_findings_to_json() {
        let findings = vec![Finding {
            package: "evil-pkg".to_string(),
            version: "1.0.0".to_string(),
            status: Status::Vulnerable,
        }];
        let report = Report::from_findings(&findings);
        let json = report.to_json().unwrap();
        assert!(json.contains("\"vulnerable\": true"));
    }

    #[test]
    fn renders_readable_text_report() {
        let findings = vec![Finding {
            package: "evil-pkg".to_string(),
            version: "1.0.0".to_string(),
            status: Status::Vulnerable,
        }];
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
    fn stripping_ansi_codes_yields_the_same_plain_content() {
        console::set_colors_enabled(true);

        let findings = vec![Finding {
            package: "evil-pkg".to_string(),
            version: "1.0.0".to_string(),
            status: Status::Vulnerable,
        }];
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
            Finding {
                package: "evil-pkg".to_string(),
                version: "1.0.0".to_string(),
                status: Status::Vulnerable,
            },
            Finding {
                package: "safe-pkg".to_string(),
                version: "2.0.0".to_string(),
                status: Status::Sain,
            },
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
}

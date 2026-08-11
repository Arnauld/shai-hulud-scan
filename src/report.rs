//! Formats de restitution : console ANSI, fichier rapport, JSON structuré (SPEC-T02).

use console::style;
use serde::Serialize;

use crate::audit::{Finding, Status};
use crate::hunt::ThreatSignal;

/// Rapport d'audit sérialisable, indépendant du format de sortie final.
#[derive(Debug, Default, Serialize)]
pub struct Report {
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
            findings: findings.iter().map(FindingReport::from).collect(),
            threats: Vec::new(),
        }
    }

    /// Attache les signaux de Threat Hunting (SPEC-F06/F07) au rapport.
    pub fn with_threats(mut self, threats: Vec<ThreatSignal>) -> Self {
        self.threats = threats;
        self
    }

    /// Sérialise le rapport en JSON structuré (option `--json`, SPEC-T02).
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Rend le rapport en texte lisible pour la console. Coloré via codes ANSI selon
    /// `console::colors_enabled()` (auto-détection TTY, ou forcé par `--no-color` /
    /// `console::set_colors_enabled`) — utiliser `console::strip_ansi_codes` sur le
    /// résultat pour obtenir la version "texte brut" du rapport-fichier (SPEC-T02).
    pub fn render_text(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{} dépendance(s) analysée(s).\n",
            style(self.findings.len()).bold()
        ));
        for finding in &self.findings {
            if finding.vulnerable {
                out.push_str(&format!(
                    "{} {}@{}\n",
                    style("[VULNÉRABLE]").red().bold(),
                    finding.package,
                    finding.version
                ));
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

        if self.findings.iter().all(|f| !f.vulnerable) && self.threats.is_empty() {
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
        let text = report.render_text();

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
        let colored = report.render_text();
        let plain = console::strip_ansi_codes(&colored).to_string();

        assert!(colored.contains('\u{1b}'));
        assert!(!plain.contains('\u{1b}'));
        assert!(plain.contains("evil-pkg@1.0.0"));
    }
}

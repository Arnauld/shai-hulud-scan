//! Formats de restitution : console ANSI, fichier rapport, JSON structuré (SPEC-T02).

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
}

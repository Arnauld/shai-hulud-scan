//! Chargement et interrogation de la base de signatures IOC (SPEC-F01).

use std::collections::HashMap;

/// Base de signatures IOC : nom de paquet npm -> versions compromises.
#[derive(Debug, Default, Clone)]
pub struct IocDatabase {
    packages: HashMap<String, Vec<String>>,
}

impl IocDatabase {
    /// Parse un CSV au format `ecosystem,package,versions` (versions séparées par ` | `).
    pub fn from_csv(input: &str) -> Result<Self, csv::Error> {
        let mut packages: HashMap<String, Vec<String>> = HashMap::new();
        let mut reader = csv::Reader::from_reader(input.as_bytes());
        for record in reader.records() {
            let record = record?;
            let package = record.get(1).unwrap_or_default().to_string();
            let versions = record
                .get(2)
                .unwrap_or_default()
                .split('|')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            packages.entry(package).or_default().extend(versions);
        }
        Ok(Self { packages })
    }

    /// Vrai si `package@version` est référencé comme compromis.
    pub fn is_compromised(&self, package: &str, version: &str) -> bool {
        self.packages
            .get(package)
            .is_some_and(|versions| versions.iter().any(|v| v == version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pipe_separated_versions() {
        let csv = "ecosystem,package,versions\n\
                   npm,@cacheable/memory,2.2.1\n\
                   npm,@arv-bedrock/auth,1.1.7 | 1.1.8\n";
        let db = IocDatabase::from_csv(csv).unwrap();
        assert!(db.is_compromised("@cacheable/memory", "2.2.1"));
        assert!(db.is_compromised("@arv-bedrock/auth", "1.1.8"));
        assert!(!db.is_compromised("@cacheable/memory", "9.9.9"));
        assert!(!db.is_compromised("unknown-package", "1.0.0"));
    }
}

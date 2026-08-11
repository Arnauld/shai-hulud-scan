//! Chargement et interrogation de la base de signatures IOC (SPEC-F01).

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;

/// URL officielle de la base d'IOC Datadog (paquets npm malveillants connus).
pub const OFFICIAL_IOC_URL: &str = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/keyv-campaign/keyv-campaign/malicious-packages.csv";

/// Nom du fichier recherché dans le répertoire d'exécution en fallback local.
pub const LOCAL_FALLBACK_FILENAME: &str = "malicious-packages.csv";

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

    /// Charge la base IOC (SPEC-F01) : tente d'abord le téléchargement depuis l'URL
    /// officielle, puis se rabat sur `database_path` s'il est fourni, ou sur un
    /// fichier `malicious-packages.csv` présent dans le répertoire d'exécution. Si
    /// `offline` est vrai (`--offline`), le téléchargement n'est jamais tenté et la
    /// base locale est utilisée directement.
    pub async fn load(database_path: Option<&Path>, offline: bool) -> anyhow::Result<Self> {
        let cwd = std::env::current_dir()?;
        Self::load_with(database_path, &cwd, offline, || {
            download_csv(OFFICIAL_IOC_URL)
        })
        .await
    }

    async fn load_with<F, Fut>(
        database_path: Option<&Path>,
        fallback_dir: &Path,
        offline: bool,
        download: F,
    ) -> anyhow::Result<Self>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<String>>,
    {
        if offline {
            return Self::load_local_fallback(database_path, fallback_dir);
        }
        match download().await {
            Ok(csv) => Ok(Self::from_csv(&csv)?),
            Err(_) => Self::load_local_fallback(database_path, fallback_dir),
        }
    }

    fn load_local_fallback(
        database_path: Option<&Path>,
        fallback_dir: &Path,
    ) -> anyhow::Result<Self> {
        let path = match database_path {
            Some(path) => path.to_path_buf(),
            None => fallback_dir.join(LOCAL_FALLBACK_FILENAME),
        };
        let csv = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "téléchargement réseau de la base IOC échoué et aucun fichier local trouvé ({})",
                path.display()
            )
        })?;
        Ok(Self::from_csv(&csv)?)
    }
}

async fn download_csv(url: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    Ok(response.text().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CSV: &str = "ecosystem,package,versions\nnpm,evil-pkg,1.0.0\n";

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

    #[tokio::test]
    async fn uses_downloaded_csv_when_network_succeeds() {
        let empty_dir = tempfile::tempdir().unwrap();

        let db = IocDatabase::load_with(None, empty_dir.path(), false, || async {
            Ok(SAMPLE_CSV.to_string())
        })
        .await
        .unwrap();

        assert!(db.is_compromised("evil-pkg", "1.0.0"));
    }

    #[tokio::test]
    async fn falls_back_to_explicit_database_path_when_network_fails() {
        let dir = tempfile::tempdir().unwrap();
        let local_path = dir.path().join("custom.csv");
        std::fs::write(&local_path, SAMPLE_CSV).unwrap();
        let unrelated_dir = tempfile::tempdir().unwrap();

        let db = IocDatabase::load_with(Some(&local_path), unrelated_dir.path(), false, || async {
            anyhow::bail!("réseau indisponible")
        })
        .await
        .unwrap();

        assert!(db.is_compromised("evil-pkg", "1.0.0"));
    }

    #[tokio::test]
    async fn falls_back_to_execution_directory_when_no_path_given() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCAL_FALLBACK_FILENAME), SAMPLE_CSV).unwrap();

        let db = IocDatabase::load_with(None, dir.path(), false, || async {
            anyhow::bail!("réseau indisponible")
        })
        .await
        .unwrap();

        assert!(db.is_compromised("evil-pkg", "1.0.0"));
    }

    #[tokio::test]
    async fn errors_when_network_fails_and_no_local_file_is_found() {
        let empty_dir = tempfile::tempdir().unwrap();

        let result = IocDatabase::load_with(None, empty_dir.path(), false, || async {
            anyhow::bail!("réseau indisponible")
        })
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn offline_mode_never_attempts_the_download() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCAL_FALLBACK_FILENAME), SAMPLE_CSV).unwrap();

        let db = IocDatabase::load_with(None, dir.path(), true, || async {
            panic!("--offline ne doit jamais déclencher de téléchargement réseau")
        })
        .await
        .unwrap();

        assert!(db.is_compromised("evil-pkg", "1.0.0"));
    }
}

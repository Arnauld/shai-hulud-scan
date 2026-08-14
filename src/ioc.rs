//! Chargement et interrogation de la base de signatures IOC (SPEC-F01).

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use serde::Serialize;
use tracing::{error, info, warn};

/// Nom du fichier recherché dans le répertoire d'exécution en fallback local.
pub const LOCAL_FALLBACK_FILENAME: &str = "malicious-packages.csv";

/// Résultat de la comparaison d'une dépendance avec la base IOC (SPEC-F04, niveau 1).
/// Classification à trois niveaux, pas une simple bascule vulnérable/sain :
/// `Vulnerable` (paquet connu de la base mais version rencontrée non listée) est
/// **moins** sévère que `Corrompue` (correspondance exacte) — attention à l'ordre
/// historique inversé par rapport à une ancienne version de cet enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum CompromiseStatus {
    /// Le paquet n'apparaît pas du tout dans la base IOC, quelle que soit la version.
    Sain,
    /// Le paquet est référencé dans la base IOC (au moins une version compromise
    /// connue) mais pas à la version rencontrée : signal de vigilance sur un paquet
    /// ciblé par la campagne, sans confirmation exacte à cette version précise.
    Vulnerable {
        version: String,
        known_compromised_versions: Vec<String>,
    },
    /// La version rencontrée correspond exactement à une version compromise connue.
    Corrompue { version: String },
}

/// Base de signatures IOC : nom de paquet npm -> versions compromises.
#[derive(Debug, Default, Clone)]
pub struct IocDatabase {
    packages: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RemoteCsv(String, String);

impl RemoteCsv {
    pub fn new(url: impl Into<String>, raw: impl Into<String>) -> anyhow::Result<Self> {
        let url = url.into();
        let raw = raw.into();

        if raw.is_empty() {
            anyhow::bail!("raw content cannot be empty");
        }

        Ok(Self(url, raw))
    }

    pub fn url(&self) -> &str {
        &self.0
    }

    pub fn raw_content(&self) -> &str {
        &self.1
    }
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

    /// Évalue `package@version` par rapport à la base IOC (SPEC-F04, niveau 1) :
    /// `Sain` si le paquet est totalement absent de la base, `Corrompue` si la version
    /// rencontrée correspond exactement à une version listée, `Vulnerable` si le
    /// paquet est connu mais pas à cette version précise.
    pub fn evaluate_compromise(&self, package: &str, version: &str) -> CompromiseStatus {
        match self.packages.get(package) {
            None => CompromiseStatus::Sain,
            Some(known_versions) if known_versions.iter().any(|v| v == version) => {
                CompromiseStatus::Corrompue {
                    version: version.to_string(),
                }
            }
            Some(known_versions) => CompromiseStatus::Vulnerable {
                version: version.to_string(),
                known_compromised_versions: known_versions.clone(),
            },
        }
    }

    /// Charge la base IOC (SPEC-F01) : tente d'abord le téléchargement depuis
    /// `official_url` (`iocs.toml`, paramétrable via `--iocs-file`), puis se rabat sur
    /// `database_path` s'il est fourni, ou sur un fichier `malicious-packages.csv`
    /// présent dans le répertoire d'exécution. Si `offline` est vrai (`--offline`), le
    /// téléchargement n'est jamais tenté et la base locale est utilisée directement.
    pub async fn load(
        database_path: Option<&Path>,
        offline: bool,
        official_url: &str,
    ) -> anyhow::Result<Self> {
        let cwd = std::env::current_dir()?;
        Self::load_with(database_path, &cwd, offline, || download_csv(official_url)).await
    }

    async fn load_with<F, Fut>(
        database_path: Option<&Path>,
        fallback_dir: &Path,
        offline: bool,
        download: F,
    ) -> anyhow::Result<Self>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<RemoteCsv>>,
    {
        if offline {
            info!("mode --offline actif, base IOC locale utilisée sans tentative réseau");
            return Self::load_local_fallback(database_path, fallback_dir);
        }
        match download().await {
            Ok(csv) => {
                info!("Base IOC téléchargée depuis {:?}", csv.url());
                Ok(Self::from_csv(csv.raw_content())?)
            }
            Err(err) => {
                warn!(error = %err, "Téléchargement réseau de la base IOC échoué, repli sur la base locale");
                Self::load_local_fallback(database_path, fallback_dir)
            }
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
        let csv = std::fs::read_to_string(&path)
            .inspect_err(|_| error!(path = %path.display(), "aucune base IOC locale disponible"))
            .with_context(|| {
                format!(
                    "téléchargement réseau de la base IOC échoué et aucun fichier local trouvé ({})",
                    path.display()
                )
            })?;
        info!(path = %path.display(), "base IOC chargée depuis un fichier local");
        Ok(Self::from_csv(&csv)?)
    }
}

async fn download_csv(url: &str) -> anyhow::Result<RemoteCsv> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    let raw_response = RemoteCsv::new(url, response.text().await?)?;
    Ok(raw_response)
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
        assert_eq!(
            db.evaluate_compromise("@cacheable/memory", "2.2.1"),
            CompromiseStatus::Corrompue {
                version: "2.2.1".to_string()
            }
        );
        assert_eq!(
            db.evaluate_compromise("@arv-bedrock/auth", "1.1.8"),
            CompromiseStatus::Corrompue {
                version: "1.1.8".to_string()
            }
        );
        assert_eq!(
            db.evaluate_compromise("unknown-package", "1.0.0"),
            CompromiseStatus::Sain
        );
    }

    #[test]
    fn flags_a_known_package_at_an_unlisted_version_as_vulnerable_not_sain() {
        let csv = "ecosystem,package,versions\nnpm,@cacheable/memory,2.2.1 | 2.2.2\n";
        let db = IocDatabase::from_csv(csv).unwrap();

        assert_eq!(
            db.evaluate_compromise("@cacheable/memory", "9.9.9"),
            CompromiseStatus::Vulnerable {
                version: "9.9.9".to_string(),
                known_compromised_versions: vec!["2.2.1".to_string(), "2.2.2".to_string()],
            }
        );
    }

    #[tokio::test]
    async fn uses_downloaded_csv_when_network_succeeds() {
        let empty_dir = tempfile::tempdir().unwrap();

        let db = IocDatabase::load_with(None, empty_dir.path(), false, || async {
            RemoteCsv::new("https://example.com/malicious-packages.csv", SAMPLE_CSV)
        })
        .await
        .unwrap();

        assert!(matches!(
            db.evaluate_compromise("evil-pkg", "1.0.0"),
            CompromiseStatus::Corrompue { .. }
        ));
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

        assert!(matches!(
            db.evaluate_compromise("evil-pkg", "1.0.0"),
            CompromiseStatus::Corrompue { .. }
        ));
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

        assert!(matches!(
            db.evaluate_compromise("evil-pkg", "1.0.0"),
            CompromiseStatus::Corrompue { .. }
        ));
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

        assert!(matches!(
            db.evaluate_compromise("evil-pkg", "1.0.0"),
            CompromiseStatus::Corrompue { .. }
        ));
    }
}

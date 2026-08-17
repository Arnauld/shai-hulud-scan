//! Détection des occurrences trouvées à l'intérieur d'un appel `console.log`/
//! `console.error` en JS/TSX (SPEC-F05/F08), via un vrai parseur AST (`oxc_parser`)
//! plutôt que le lexer heuristique de `comments.rs` — nécessaire ici pour distinguer un
//! appel de fonction réel (`console.log("npm install ...")`, juste un affichage,
//! jamais exécuté comme commande) d'une simple chaîne de caractères contenant
//! "console.log" ailleurs dans le fichier. Scope volontairement restreint aux
//! extensions `.js` et `.tsx` (les seules demandées) plutôt qu'à toute la famille
//! `CStyle` de `comments.rs` (`.jsx`/`.ts`/`.mjs`/`.cjs`).

use std::ops::Range;
use std::path::Path;

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

/// Vrai si l'extension de `path` est `.js` ou `.tsx` (portée volontairement restreinte,
/// voir en-tête du module).
pub fn is_console_scan_candidate(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("js") || ext.eq_ignore_ascii_case("tsx"))
}

fn is_console_log_or_error(callee: &Expression) -> bool {
    let Expression::StaticMemberExpression(member) = callee else {
        return false;
    };
    let Expression::Identifier(object) = &member.object else {
        return false;
    };
    object.name == "console" && (member.property.name == "log" || member.property.name == "error")
}

#[derive(Default)]
struct ConsoleCallCollector {
    spans: Vec<Range<usize>>,
}

impl<'a> Visit<'a> for ConsoleCallCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if is_console_log_or_error(&call.callee) {
            let span = call.span();
            self.spans.push(span.start as usize..span.end as usize);
        }
        walk::walk_call_expression(self, call);
    }
}

/// Intervalles d'octets couverts par un appel `console.log(...)`/`console.error(...)`
/// dans `content` (span complet de l'appel, arguments inclus) — une correspondance
/// entièrement contenue dans l'un de ces intervalles n'est qu'affichée/journalisée,
/// jamais exécutée comme commande. `path` sert uniquement à déterminer le type de
/// source (`.js` vs `.tsx`, JSX activé ou non) attendu par le parseur. Retourne un
/// vecteur vide si `path` n'est pas une extension couverte (voir
/// [`is_console_scan_candidate`]) ou si `content` ne parse pas — au pire, aucune
/// correspondance n'est marquée comme "dans un console.log", comportement historique
/// conservé (pas d'erreur remontée, un fichier non parsable ne doit pas faire échouer
/// le scan).
pub fn console_log_spans(content: &str, path: &Path) -> Vec<Range<usize>> {
    if !is_console_scan_candidate(path) {
        return Vec::new();
    }
    let Ok(source_type) = SourceType::from_path(path) else {
        return Vec::new();
    };

    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, content, source_type).parse();

    let mut collector = ConsoleCallCollector::default();
    collector.visit_program(&ret.program);
    collector.spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_js_and_tsx_only() {
        assert!(is_console_scan_candidate(Path::new("app.js")));
        assert!(is_console_scan_candidate(Path::new("App.tsx")));
        assert!(!is_console_scan_candidate(Path::new("app.jsx")));
        assert!(!is_console_scan_candidate(Path::new("app.ts")));
        assert!(!is_console_scan_candidate(Path::new("README.md")));
    }

    #[test]
    fn collects_the_span_of_a_console_log_call() {
        let content = r#"console.log("run npm install to get started");"#;
        let spans = console_log_spans(content, Path::new("app.js"));

        let marker = content.find("npm install").unwrap();
        assert!(spans
            .iter()
            .any(|span| span.start <= marker && marker + "npm install".len() <= span.end));
    }

    #[test]
    fn collects_the_span_of_a_console_error_call() {
        let content = r#"console.error("blocked call to npm-cache.com");"#;
        let spans = console_log_spans(content, Path::new("app.js"));

        let marker = content.find("npm-cache.com").unwrap();
        assert!(spans
            .iter()
            .any(|span| span.start <= marker && marker + "npm-cache.com".len() <= span.end));
    }

    #[test]
    fn does_not_flag_a_real_function_call_as_a_console_log() {
        let content = r#"exec("npm install");"#;
        let spans = console_log_spans(content, Path::new("app.js"));
        assert!(spans.is_empty());
    }

    #[test]
    fn works_on_tsx_with_jsx_syntax() {
        let content = r#"
            const App = () => {
                console.log("npm install lodash");
                return <div>hello</div>;
            };
        "#;
        let spans = console_log_spans(content, Path::new("App.tsx"));

        let marker = content.find("npm install").unwrap();
        assert!(spans
            .iter()
            .any(|span| span.start <= marker && marker + "npm install".len() <= span.end));
    }
}

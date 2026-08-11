//! Détection passive de commandes d'installation dans le code source (SPEC-F05).

use std::sync::LazyLock;

use regex::Regex;

static NPM_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"npm\s(install|ci|update)").unwrap());
static YARN_INSTALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"yarn\s(install|add|ci|upgrade|run)").unwrap());

/// Vrai si `content` contient une instruction d'installation npm ou yarn directe.
pub fn contains_install_command(content: &str) -> bool {
    NPM_INSTALL.is_match(content) || YARN_INSTALL.is_match(content)
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
}

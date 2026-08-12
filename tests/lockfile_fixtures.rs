//! Tests d'intégration du parsing de lockfiles contre des fixtures réelles
//! (`test-data/`, voir `test-data/README.md` pour la provenance), afin de garantir
//! l'exhaustivité de `lockfile.rs` face aux formats et cas du monde réel (SPEC-F04),
//! au-delà des cas synthétiques déjà couverts par les tests unitaires du module.

use std::path::Path;

use shai_hulud_guard::lockfile::{parse_npm_lock, parse_yarn_lock};

fn fixture(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-data")
        .join(relative_path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("impossible de lire la fixture {}: {err}", path.display()))
}

#[test]
fn parses_real_npm_lockfile_version_1() {
    let content = fixture("npm-v1-heroku-cra-node/package-lock.json");
    let deps = parse_npm_lock(&content).expect("lockfile v1 valide");
    assert!(!deps.is_empty());
    assert!(deps.iter().any(|d| d.name == "express"));
}

#[test]
fn parses_real_npm_lockfile_version_2_including_nested_version_conflicts() {
    let content = fixture("npm-v2-bootstrap-npm-starter/package-lock.json");
    let deps = parse_npm_lock(&content).expect("lockfile v2 valide");
    assert!(!deps.is_empty());

    // Conflit de version réel présent dans cette fixture : "ansi-styles" est résolu à
    // 3 emplacements différents (hissé + deux copies imbriquées), avec des versions
    // différentes (4.3.0 vs 3.2.1) — cas de "télescopage" de dépendance transitive.
    let ansi_styles_versions: Vec<&str> = deps
        .iter()
        .filter(|d| d.name == "ansi-styles")
        .map(|d| d.version.as_str())
        .collect();
    assert!(ansi_styles_versions.len() >= 2);
    assert!(ansi_styles_versions.contains(&"4.3.0"));
    assert!(ansi_styles_versions.contains(&"3.2.1"));
}

#[test]
fn parses_real_npm_lockfile_version_3() {
    let content = fixture("npm-v3-vscode-helloworld-sample/package-lock.json");
    let deps = parse_npm_lock(&content).expect("lockfile v3 valide");
    assert!(!deps.is_empty());
    assert!(deps.iter().any(|d| d.name == "@types/vscode"));
}

#[test]
fn parses_npm_lockfile_with_no_dependencies_without_error() {
    let content = fixture("npm-v3-empty-stackblitz-node/package-lock.json");
    let deps = parse_npm_lock(&content).expect("lockfile v3 vide mais valide");
    assert!(deps.is_empty());
}

#[test]
fn parses_real_yarn_classic_lockfile() {
    let content = fixture("yarn-classic-serve-handler/yarn.lock");
    let deps = parse_yarn_lock(&content);
    assert!(!deps.is_empty());
}

#[test]
fn parses_real_yarn_berry_lockfile_and_ignores_metadata_block() {
    let content = fixture("yarn-berry-clipanion/yarn.lock");
    let deps = parse_yarn_lock(&content);
    assert!(!deps.is_empty());
    assert!(deps.iter().all(|d| d.name != "__metadata"));
}

#[test]
fn parses_large_real_npm_lockfile_version_3_with_many_nested_conflicts() {
    let content = fixture("project-01/package-lock.json");
    let deps = parse_npm_lock(&content).expect("lockfile v3 valide");

    // Échelle réelle : ~1160 paquets dans le lockfile source.
    assert!(deps.len() > 1000);
    assert!(deps
        .iter()
        .any(|d| d.name == "@angular/core" && d.version == "20.3.15"));

    // Conflit de version réel sur une dépendance transitive largement partagée :
    // "semver" est résolu à 3 versions différentes selon l'emplacement imbriqué
    // (hissé à la racine, imbriqué sous @babel/core, imbriqué sous make-dir).
    let semver_versions: std::collections::HashSet<&str> = deps
        .iter()
        .filter(|d| d.name == "semver")
        .map(|d| d.version.as_str())
        .collect();
    assert!(semver_versions.contains("5.7.2"));
    assert!(semver_versions.contains("6.3.1"));
    assert!(semver_versions.contains("7.7.2"));
}

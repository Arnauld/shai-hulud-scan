# CLAUDE.md

## Projet
`shai-hulud-guard` : CLI Rust d'audit de sécurité détectant la compromission des dépôts npm/yarn par le ver de supply-chain **Shai-Hulud** (et ses variantes, ex. "2.0 / Second Coming"). Binaire unique, statique, multi-plateforme (Linux musl, macOS universal, Windows).

**La source de vérité fonctionnelle est `specs.md`.** Toujours vérifier ce fichier avant d'implémenter une fonctionnalité ; le mettre à jour si le comportement implémenté diverge (nouvelle variante du ver, nouveau flag CLI, etc.).

## État du dépôt
Toutes les specs fonctionnelles (SPEC-F01 à F07) et techniques (SPEC-T01 à T03) sont implémentées : chargement IOC réseau + fallback + `--offline`, parcours `ignore`, découverte npm/yarn, audit lockfiles + simulation `npm install`, scan regex, moteur de Threat Hunting, sortie console colorée/JSON/rapport-fichier avec barres `indicatif`, et packaging cross-plateforme (voir ci-dessous).

## Architecture cible (voir specs.md pour le détail)
- `ioc` — chargement/parse de la base CSV d'IOC (réseau + fallback local), `HashMap<String, Vec<String>>` (SPEC-F01). Les signatures évoluent vite : ne rien figer en dur, prévoir un fichier de config externe (`iocs.toml`) pour les chaînes/fichiers suspects du Threat Hunting (SPEC-F06/F07).
- `walker` — parcours de fichiers via la crate `ignore` (SPEC-F02).
- `discovery` — détection des projets npm/yarn (SPEC-F03).
- `audit` — analyse des lockfiles existants + simulation `npm install --package-lock-only` (SPEC-F04).
- `scan` — détection passive de commandes d'install dans le code source via `regex` (SPEC-F05).
- `hunt` — recherche active de signaux malveillants sur disque (fichiers payload, hooks, persistance macOS/CI) (SPEC-F06/F07).
- `report` — sortie console ANSI, `--report-file`, `--json` (SPEC-T02).
- `cli` — point d'entrée, orchestration `tokio` + sémaphore de concurrence (SPEC-T01).

## Crates de référence imposées par la spec
`tokio` (async/parallélisme), `ignore` (parcours fichiers, moteur ripgrep), `regex`, `indicatif` + `console` (progress bars, ANSI), `clap` (CLI, derive), `serde`/`serde_json`/`csv` (JSON, parsing IOC), `reqwest` (rustls, téléchargement IOC), `anyhow`/`thiserror` (erreurs), `dirs` (chemins `~/Library/LaunchAgents`).

## Commandes
```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

## Packaging cross-plateforme (SPEC-T03)
Binaire statique et autonome sur 3 cibles, chacune liée statiquement via `.cargo/config.toml`
(`target-feature=+crt-static`, pas de dépendance glibc/CRT sur la machine cible) :
- **Linux** : `cargo build --release --target x86_64-unknown-linux-musl` (nécessite `musl-tools`).
- **macOS universal** (Intel + Apple Silicon) : `./scripts/build-macos-universal.sh` — build les
  deux cibles natives (`x86_64-apple-darwin`, `aarch64-apple-darwin`) et les fusionne via `lipo`
  dans `target/universal/release/shai-hulud-guard`.
- **Windows** : `cargo build --release --target x86_64-pc-windows-msvc` (nécessite le toolchain MSVC).

Le musl et le MSVC ne sont pas cross-compilables depuis ce Mac (ni `musl-gcc` ni toolchain MSVC
disponibles) : `.github/workflows/release.yml` construit les 3 cibles sur leur runner natif
(ubuntu/windows/macos) à chaque tag `v*.*.*`, et publie les binaires sur la release GitHub.

## Conventions de code
- Typage fort, pas de `unwrap()`/`expect()` hors tests — remonter les erreurs via `Result` (`thiserror`/`anyhow` à choisir et documenter ici une fois tranché).
- Chaque module public doit être testable unitairement (mock du système de fichiers via `tempfile` pour les tests d'intégration lockfile/IOC).
- Toute action destructive ou risquée (écriture/suppression de lockfiles réels, `npm install` en simulation) doit rester confinée à un répertoire temporaire et restaurer l'état d'origine (SPEC-F04) — ne jamais laisser un projet utilisateur dans un état modifié après un scan.
- Pas de commentaires sauf pour justifier un choix non évident (ex. pourquoi `--legacy-peer-deps` est requis).

## Workflow de validation obligatoire
Toute modification de code doit suivre systématiquement ce cycle avant d'être considérée terminée :
1. Exécuter `cargo test` (et `cargo clippy --all-targets -- -D warnings`) — la modification n'est validée que si tous les tests passent.
2. En cas de succès uniquement, créer un commit git respectant les [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `refactor:`, `test:`, `chore:`, …).
3. En cas d'échec des tests, corriger avant de commit — ne jamais committer un état rouge.

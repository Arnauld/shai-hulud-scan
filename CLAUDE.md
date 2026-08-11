# CLAUDE.md

## Projet
`shai-hulud-guard` : CLI Rust d'audit de sécurité détectant la compromission des dépôts npm/yarn par le ver de supply-chain **Shai-Hulud** (et ses variantes, ex. "2.0 / Second Coming"). Binaire unique, statique, multi-plateforme (Linux musl, macOS universal, Windows).

**La source de vérité fonctionnelle est `specs.md`.** Toujours vérifier ce fichier avant d'implémenter une fonctionnalité ; le mettre à jour si le comportement implémenté diverge (nouvelle variante du ver, nouveau flag CLI, etc.).

## État du dépôt
Actuellement seule la spec existe, aucun code Rust n'a encore été généré. La structure Cargo (`Cargo.toml`, `src/`) reste à créer conformément à SPEC-T01/T02/T03.

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
`tokio` (async/parallélisme), `ignore` (parcours fichiers, moteur ripgrep), `regex`, `indicatif` (progress bars), `clap` (CLI, à confirmer), `serde`/`serde_json` (JSON), un client HTTP simple (ex. `reqwest` ou `ureq`) pour le téléchargement de la base IOC.

## Commandes
```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```
Cibles de cross-compilation (SPEC-T03) : `x86_64-unknown-linux-musl`, macOS universal (x86_64 + aarch64), `x86_64-pc-windows-msvc`.

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

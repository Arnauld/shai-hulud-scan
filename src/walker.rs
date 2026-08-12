//! Parcours de fichiers ultra-rapide via la crate `ignore` (SPEC-F02).

use std::path::Path;

use ignore::{DirEntry, WalkBuilder};
use indicatif::ProgressBar;
use tracing::{debug, warn};

/// Parcourt récursivement `root` en respectant les règles `.gitignore` (sauf
/// `no_ignore: true`, `--no-ignore`, SPEC-F02 — nécessaire pour ne pas manquer un
/// sous-dépôt intentionnellement ignoré, ex. un clone imbriqué) et en élaguant les
/// dossiers cachés, sans dépendre de commandes système externes. `progress` est
/// incrémentée d'une unité par entrée visitée (SPEC-T02) — passer
/// `ProgressBar::hidden()` pour un parcours silencieux (ex. en test). Chaque entrée
/// visitée est journalisée au niveau `DEBUG` (visible uniquement via `--verbose`,
/// SPEC-T04). Toute entrée qui ne peut pas être lue (permissions insuffisantes,
/// chemin trop long — un cas classique sous Windows au-delà de `MAX_PATH` — boucle
/// de symlinks...) est journalisée en `WARN`, toujours visible par défaut, plutôt
/// que d'être silencieusement absente du parcours sans explication. Les répertoires
/// volontairement élagués par les règles `.gitignore`/`.ignore`/fichiers cachés (pas
/// des erreurs, un choix délibéré du moteur `ignore`) sont eux visibles en journalisant
/// la façade `log` interne de cette crate vers `tracing` (voir `main::init_logging`,
/// directive `ignore=debug` avec `--verbose`).
pub fn walk<'a>(
    root: &Path,
    progress: &'a ProgressBar,
    no_ignore: bool,
) -> impl Iterator<Item = DirEntry> + 'a {
    WalkBuilder::new(root)
        .git_ignore(!no_ignore)
        .ignore(!no_ignore)
        .parents(!no_ignore)
        .build()
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                // Le chemin concerné est déjà inclus dans l'affichage de `err`
                // (variantes `WithPath`/`WithLineNumber` de `ignore::Error`).
                warn!(
                    error = %err,
                    "entrée ignorée lors du parcours (non lisible : permissions, chemin trop long, boucle de symlinks...)"
                );
                None
            }
        })
        .inspect(move |entry| {
            progress.inc(1);
            debug!(path = %entry.path().display(), "fichier analysé");
        })
}

/// Variante de [`walk`] incluant les fichiers et dossiers cachés, élagués par défaut
/// par la crate `ignore` — ce qui rend `.env*` invisible au parcours standard. `.git/`
/// reste exclu (jamais utile à inspecter, potentiellement volumineux). Réservée aux
/// vérifications qui doivent explicitement voir les dotfiles (SPEC-F08). `no_ignore`
/// a la même signification que pour [`walk`] (`--no-ignore`, SPEC-F02) : désactive les
/// règles `.gitignore`/`.ignore`/parent, pour ne pas manquer un sous-dépôt cloné
/// volontairement ignoré.
pub fn walk_including_hidden<'a>(
    root: &Path,
    progress: &'a ProgressBar,
    no_ignore: bool,
) -> impl Iterator<Item = DirEntry> + 'a {
    WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(!no_ignore)
        .ignore(!no_ignore)
        .parents(!no_ignore)
        .filter_entry(|entry| entry.file_name() != ".git")
        .build()
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                warn!(
                    error = %err,
                    "entrée ignorée lors du parcours (non lisible : permissions, chemin trop long, boucle de symlinks...)"
                );
                None
            }
        })
        .inspect(move |entry| {
            progress.inc(1);
            debug!(path = %entry.path().display(), "fichier analysé (dotfiles inclus)");
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_files_in_a_temp_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let progress = ProgressBar::hidden();
        let found = walk(dir.path(), &progress, false)
            .filter(|entry| entry.file_name() == "package.json")
            .count();
        assert_eq!(found, 1);
        assert_eq!(progress.position(), 2); // le répertoire racine + package.json
    }
}

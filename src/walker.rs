//! Parcours de fichiers ultra-rapide via la crate `ignore` (SPEC-F02).

use std::path::Path;

use ignore::{DirEntry, WalkBuilder};
use indicatif::ProgressBar;
use tracing::{debug, warn};

/// Parcourt récursivement `root` en respectant les règles `.gitignore` et en
/// élaguant les dossiers cachés, sans dépendre de commandes système externes.
/// `progress` est incrémentée d'une unité par entrée visitée (SPEC-T02) — passer
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
pub fn walk<'a>(root: &Path, progress: &'a ProgressBar) -> impl Iterator<Item = DirEntry> + 'a {
    WalkBuilder::new(root)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_files_in_a_temp_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let progress = ProgressBar::hidden();
        let found = walk(dir.path(), &progress)
            .filter(|entry| entry.file_name() == "package.json")
            .count();
        assert_eq!(found, 1);
        assert_eq!(progress.position(), 2); // le répertoire racine + package.json
    }
}

//! Parcours de fichiers ultra-rapide via la crate `ignore` (SPEC-F02).

use std::path::Path;

use ignore::{DirEntry, WalkBuilder};
use indicatif::ProgressBar;

/// Parcourt récursivement `root` en respectant les règles `.gitignore` et en
/// élaguant les dossiers cachés, sans dépendre de commandes système externes.
/// `progress` est incrémentée d'une unité par entrée visitée (SPEC-T02) — passer
/// `ProgressBar::hidden()` pour un parcours silencieux (ex. en test). Chaque entrée
/// est journalisée au niveau `DEBUG` (visible uniquement via `--verbose`, SPEC-T04).
pub fn walk<'a>(root: &Path, progress: &'a ProgressBar) -> impl Iterator<Item = DirEntry> + 'a {
    WalkBuilder::new(root)
        .build()
        .filter_map(Result::ok)
        .inspect(move |entry| {
            progress.inc(1);
            tracing::debug!(path = %entry.path().display(), "fichier analysé");
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

//! Parcours de fichiers ultra-rapide via la crate `ignore` (SPEC-F02).

use std::io::ErrorKind;
use std::path::Path;

use ignore::{DirEntry, WalkBuilder};
use indicatif::ProgressBar;
use tracing::{debug, warn};

/// Chemin associé à une erreur de parcours, si `ignore::Error` en porte un
/// (`WithPath`/`WithLineNumber`/`WithDepth` s'enveloppent les uns les autres selon le
/// contexte où l'erreur a été rencontrée).
fn walk_error_path(err: &ignore::Error) -> Option<&Path> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            walk_error_path(err)
        }
        ignore::Error::Partial(errs) if errs.len() == 1 => walk_error_path(&errs[0]),
        _ => None,
    }
}

/// Journalise une entrée de parcours illisible en `WARN` (toujours visible par
/// défaut, SPEC-T04). Cas "Accès refusé" (`ErrorKind::PermissionDenied` — normalisé
/// par la std lib depuis `EACCES` sur Unix et `ERROR_ACCESS_DENIED`/os error 5 sous
/// Windows, très fréquent là-bas sur les dossiers système type `C:\Program Files\...`)
/// : message court avec juste le chemin, sans le texte d'erreur OS verbeux. Les autres
/// causes (chemin trop long, boucle de symlinks...) gardent le message détaillé
/// d'origine — on ne sait pas les distinguer aussi proprement.
fn log_walk_error(err: ignore::Error) {
    let is_permission_denied = err
        .io_error()
        .is_some_and(|io_err| io_err.kind() == ErrorKind::PermissionDenied);

    if is_permission_denied {
        match walk_error_path(&err) {
            Some(path) => {
                warn!(path = %path.display(), "entrée ignorée lors du parcours (accès refusé)");
            }
            None => warn!(error = %err, "entrée ignorée lors du parcours (accès refusé)"),
        }
        return;
    }

    // Le chemin concerné est déjà inclus dans l'affichage de `err`
    // (variantes `WithPath`/`WithLineNumber` de `ignore::Error`).
    warn!(
        error = %err,
        "entrée ignorée lors du parcours (non lisible : permissions, chemin trop long, boucle de symlinks...)"
    );
}

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
                log_walk_error(err);
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
                log_walk_error(err);
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

    #[test]
    fn extracts_the_path_from_a_permission_denied_error() {
        let io_err = std::io::Error::new(
            ErrorKind::PermissionDenied,
            "Access is denied. (os error 5)",
        );
        let err = ignore::Error::WithPath {
            path: std::path::PathBuf::from(r"C:\Program Files\Foo"),
            err: Box::new(ignore::Error::Io(io_err)),
        };

        assert_eq!(err.io_error().unwrap().kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            walk_error_path(&err),
            Some(Path::new(r"C:\Program Files\Foo"))
        );
    }

    #[test]
    fn does_not_flag_a_non_permission_io_error_as_access_denied() {
        let io_err = std::io::Error::new(ErrorKind::InvalidInput, "chemin trop long");
        let err = ignore::Error::WithPath {
            path: std::path::PathBuf::from("/some/very/long/path"),
            err: Box::new(ignore::Error::Io(io_err)),
        };

        assert_ne!(err.io_error().unwrap().kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn finds_no_path_for_a_symlink_loop_error() {
        let err = ignore::Error::Loop {
            ancestor: std::path::PathBuf::from("/a"),
            child: std::path::PathBuf::from("/a/b/a"),
        };

        assert!(err.io_error().is_none());
        assert_eq!(walk_error_path(&err), None);
    }
}

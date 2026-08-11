//! Parcours de fichiers ultra-rapide via la crate `ignore` (SPEC-F02).

use std::path::Path;

use ignore::{DirEntry, WalkBuilder};

/// Parcourt récursivement `root` en respectant les règles `.gitignore` et en
/// élaguant les dossiers cachés, sans dépendre de commandes système externes.
pub fn walk(root: &Path) -> impl Iterator<Item = DirEntry> {
    WalkBuilder::new(root).build().filter_map(Result::ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_files_in_a_temp_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let found = walk(dir.path())
            .filter(|entry| entry.file_name() == "package.json")
            .count();
        assert_eq!(found, 1);
    }
}

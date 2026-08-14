//! Indicateur de progression texte minimal pour le parcours de fichiers (SPEC-T02) —
//! remplace la barre indéterminée `indicatif` pour ce cas précis : son rendu (gestion
//! du curseur/redessin de ligne) ne fonctionne pas correctement sur certains
//! terminaux Windows, produisant une sortie illisible entrecoupée des lignes de log.
//! Un simple flux de points ajoutés sur la même ligne, avec un récapitulatif tous les
//! 50 points, ne dépend d'aucune fonctionnalité terminal au-delà d'un `print!`/flush
//! basique — garanti de fonctionner partout, y compris en sortie redirigée.

use std::cell::Cell;
use std::io::Write;

const BATCH_SIZE: u64 = 50;

/// Compteur de progression texte. `enabled: false` (ex. `--no-color`, ou usage
/// interne silencieux comme l'audit `node_modules`) rend `inc`/`finish` no-op côté
/// affichage, mais `position()` continue de refléter le nombre réel d'appels à `inc`.
pub struct DotProgress {
    count: Cell<u64>,
    enabled: bool,
}

impl DotProgress {
    pub fn new(enabled: bool) -> Self {
        Self {
            count: Cell::new(0),
            enabled,
        }
    }

    /// Incrémente le compteur d'une unité et, si activé, ajoute un `.` sur la ligne
    /// courante (stderr, jamais stdout — cohérent avec les logs `tracing`, SPEC-T04).
    /// Tous les `BATCH_SIZE` points, imprime un récapitulatif `BATCH_SIZE/total` puis
    /// passe à la ligne.
    pub fn inc(&self) {
        let next = self.count.get() + 1;
        self.count.set(next);
        if !self.enabled {
            return;
        }
        eprint!(".");
        let _ = std::io::stderr().flush();
        if next.is_multiple_of(BATCH_SIZE) {
            eprintln!(" {BATCH_SIZE}/{next}");
        }
    }

    pub fn position(&self) -> u64 {
        self.count.get()
    }

    /// Termine l'affichage : si un lot partiel de points est en attente (position pas
    /// multiple de `BATCH_SIZE`), imprime son récapitulatif et passe à la ligne — sans
    /// quoi la dernière ligne de points resterait sans retour à la ligne ni total.
    pub fn finish(&self) {
        if !self.enabled {
            return;
        }
        let total = self.count.get();
        let remainder = total % BATCH_SIZE;
        if remainder != 0 {
            eprintln!(" {remainder}/{total}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_tracks_the_number_of_increments_even_when_disabled() {
        let progress = DotProgress::new(false);
        for _ in 0..73 {
            progress.inc();
        }
        assert_eq!(progress.position(), 73);
    }

    #[test]
    fn position_tracks_increments_when_enabled_too() {
        let progress = DotProgress::new(true);
        for _ in 0..3 {
            progress.inc();
        }
        assert_eq!(progress.position(), 3);
    }

    #[test]
    fn finish_is_a_no_op_when_disabled() {
        // Ne doit pas paniquer, ni écrire quoi que ce soit d'observable.
        let progress = DotProgress::new(false);
        progress.inc();
        progress.finish();
    }
}

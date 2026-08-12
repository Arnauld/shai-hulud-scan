//! Interface en ligne de commande (SPEC-T01/T02/T04/T05).

use std::path::PathBuf;

use clap::Parser;

use crate::report::ReportLevel;

/// shai-hulud-guard : audit de sécurité des dépôts npm/yarn contre la compromission Shai-Hulud.
#[derive(Debug, Parser)]
#[command(name = "shai-hulud-guard", version, about)]
pub struct Cli {
    /// Répertoire racine à analyser.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Fichier CSV de signatures IOC local (fallback si le téléchargement échoue).
    #[arg(long)]
    pub database: Option<PathBuf>,

    /// Force l'utilisation de la base IOC locale (`--database` ou
    /// `malicious-packages.csv` dans le répertoire d'exécution) sans jamais tenter
    /// de téléchargement réseau.
    #[arg(long)]
    pub offline: bool,

    /// Écrit un rapport texte brut (sans codes ANSI) dans le fichier indiqué.
    #[arg(long)]
    pub report_file: Option<PathBuf>,

    /// Sort les résultats au format JSON structuré.
    #[arg(long)]
    pub json: bool,

    /// Désactive la sortie colorée ANSI.
    #[arg(long)]
    pub no_color: bool,

    /// Nombre maximal de simulations `npm install` concurrentes (sémaphore, SPEC-T01).
    #[arg(long, default_value_t = 4)]
    pub workers: usize,

    /// Délai maximal (secondes) accordé à chaque simulation `npm install` avant
    /// abandon (SPEC-F04). Une résolution réseau lente ou bloquée sur un seul projet
    /// ne doit jamais empêcher le reste du scan de se terminer.
    #[arg(long, default_value_t = 120)]
    pub npm_timeout: u64,

    /// Active le niveau de log DEBUG et journalise chaque fichier analysé pendant
    /// le parcours (SPEC-T04). Les logs sont toujours émis sur stderr. `RUST_LOG`
    /// prime sur ce flag si défini.
    #[arg(short, long)]
    pub verbose: bool,

    /// Écrit également les logs dans ce fichier, toujours au niveau DEBUG
    /// (indépendamment de `--verbose`, qui ne contrôle que la console), pour pouvoir
    /// suivre l'avancement d'un scan en cours avec `tail -f` (SPEC-T04). Vient en plus
    /// de la sortie stderr habituelle, jamais à sa place.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Niveau de détail du rapport (console / `--report-file`), indépendant de
    /// `--verbose` : réutilise l'échelle `error < warn < info < debug` (SPEC-T05).
    /// Par défaut `debug` (verbose) : liste aussi les dépendances saines, pas
    /// seulement les vulnérables.
    #[arg(long, value_enum, default_value = "debug")]
    pub report_level: ReportLevel,
}

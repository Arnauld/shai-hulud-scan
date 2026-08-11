//! Interface en ligne de commande (SPEC-T01/T02).

use std::path::PathBuf;

use clap::Parser;

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
}

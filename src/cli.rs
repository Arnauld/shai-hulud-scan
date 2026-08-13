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

    /// Fichier TOML de signatures de Threat Hunting (fichiers/hashes/marqueurs/regex,
    /// SPEC-F06/F07/F08), fusionné champ par champ par-dessus les valeurs par défaut
    /// embarquées dans le binaire (`iocs.toml` du dépôt) — toute clé absente du
    /// fichier fourni garde sa valeur par défaut. Distinct de `--database`, qui
    /// concerne la base CSV des paquets npm compromis (SPEC-F01).
    #[arg(long)]
    pub iocs_file: Option<PathBuf>,

    /// Écrit un rapport texte brut (sans codes ANSI) dans le fichier indiqué.
    #[arg(long)]
    pub report_file: Option<PathBuf>,

    /// Sort les résultats au format JSON structuré.
    #[arg(long)]
    pub json: bool,

    /// Désactive la sortie colorée ANSI.
    #[arg(long)]
    pub no_color: bool,

    /// Ne pas respecter les règles `.gitignore`/`.ignore`/parent (SPEC-F02) : sans ce
    /// flag, un sous-dépôt intentionnellement ignoré (clone imbriqué, dépendance
    /// vendored...) est silencieusement absent de la découverte de projets, de l'audit
    /// `node_modules` et du scan passif (SPEC-F05/F08).
    #[arg(long)]
    pub no_ignore: bool,

    /// Nombre maximal de simulations `npm install` concurrentes (sémaphore, SPEC-T01).
    #[arg(long, default_value_t = 4)]
    pub workers: usize,

    /// Délai maximal (secondes) accordé à chaque simulation `npm install` avant
    /// abandon (SPEC-F04). Une résolution réseau lente ou bloquée sur un seul projet
    /// ne doit jamais empêcher le reste du scan de se terminer.
    #[arg(long, default_value_t = 120)]
    pub npm_timeout: u64,

    /// Chemin complet vers l'exécutable npm à utiliser pour la simulation
    /// d'installation (SPEC-F04 niveau 2). Par défaut, `npm` est recherché dans le
    /// PATH. Sa disponibilité est systématiquement vérifiée au démarrage et
    /// journalisée en INFO ; si indisponible, la simulation est entièrement ignorée.
    #[arg(long)]
    pub npm_path: Option<PathBuf>,

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

    /// Directive de filtrage `tracing` explicite (syntaxe `RUST_LOG`, ex.
    /// `"info,shai_hulud_guard=debug"`) pour la sortie console (SPEC-T04). Si fournie,
    /// supplante `--verbose`. `RUST_LOG` reste prioritaire sur ce flag s'il est défini.
    #[arg(long)]
    pub log_console_directive: Option<String>,

    /// Directive de filtrage `tracing` explicite (syntaxe `RUST_LOG`) pour le fichier
    /// de log (`--log-file`) : remplace la valeur par défaut, toujours DEBUG pour ce
    /// binaire (SPEC-T04). Sans effet si `--log-file` n'est pas fourni.
    #[arg(long)]
    pub log_file_directive: Option<String>,

    /// Niveau de détail du rapport (console / `--report-file`), indépendant de
    /// `--verbose` : réutilise l'échelle `error < warn < info < debug` (SPEC-T05).
    /// Par défaut `debug` (verbose) : liste aussi les dépendances saines, pas
    /// seulement les vulnérables.
    #[arg(long, value_enum, default_value = "debug")]
    pub report_level: ReportLevel,
}

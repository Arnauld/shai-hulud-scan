//! Recherche active de signaux malveillants connus sur le disque (SPEC-F06/F07).
//!
//! Ces listes évoluent vite avec les campagnes ; elles sont volontairement regroupées
//! ici pour être externalisables plus tard vers un fichier de config (`iocs.toml`)
//! sans toucher au reste du moteur de Threat Hunting.

/// Fichiers de charge utile connus, recherchés à la racine du workspace et des projets.
pub const SUSPICIOUS_FILENAMES: &[&str] = &[
    "setup.mjs",
    "Math_Symbol.js",
    "setup_bun.js",
    "bun_environment.js",
];

/// Chaîne recherchée dans les hooks de `<pkg_dir>/node_modules/*/package.json`.
pub const SUSPICIOUS_HOOK_MARKER: &str = "setup.mjs";

/// Chaîne recherchée dans les LaunchAgents macOS (`~/Library/LaunchAgents/`).
pub const SUSPICIOUS_LAUNCH_AGENT_MARKER: &str = "gh-token-monitor";

/// Fichiers d'exfiltration générés localement par la vague "Second Coming" (SPEC-F07).
pub const EXFIL_ARTIFACT_FILENAMES: &[&str] = &[
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json",
    "actionsSecrets.json",
    "data.json",
];

/// Noms de workflows GitHub Actions malveillants connus, injectés dans `.github/workflows/`.
pub const SUSPICIOUS_WORKFLOW_FILENAMES: &[&str] = &["shai-hulud-workflow.yml", "discussion.yaml"];

/// Dossier de cache caché utilisé pour dissimuler un binaire TruffleHog détourné.
pub const SUSPICIOUS_CACHE_DIRNAME: &str = ".truffler-cache";

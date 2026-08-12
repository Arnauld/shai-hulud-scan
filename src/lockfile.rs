//! Parsing des lockfiles NPM (v1/v2/v3) et Yarn (Classic v1 / Berry v2+) — SPEC-F04 niveau 1.
//!
//! Le format `yarn.lock` n'est pas du YAML valide (clés multiples séparées par des
//! virgules, guillemets optionnels) : un décodeur linéaire dédié est écrit ici plutôt
//! que de dépendre d'un parseur YAML générique, conformément à SPEC-F04.

use std::collections::HashSet;

use serde_json::Value;

/// Une dépendance résolue extraite d'un lockfile, prête à être vérifiée contre l'IOC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockedDependency {
    pub name: String,
    pub version: String,
    /// URL du champ `resolved` (npm, Yarn Classic), quand présente — absente pour
    /// Yarn Berry, qui ne stocke pas d'URL de registre explicite dans le lockfile
    /// (SPEC-F08, détournement de registre).
    pub resolved: Option<String>,
}

/// Parse un `package-lock.json`, formats v1 (`dependencies` imbriquées) et v2/v3
/// (`packages` à plat, clés `node_modules/<pkg>`).
pub fn parse_npm_lock(content: &str) -> serde_json::Result<Vec<LockedDependency>> {
    let root: Value = serde_json::from_str(content)?;

    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        let deps = packages
            .iter()
            .filter(|(path, _)| !path.is_empty())
            .filter_map(|(path, entry)| {
                let version = entry.get("version")?.as_str()?.to_string();
                let resolved = entry
                    .get("resolved")
                    .and_then(Value::as_str)
                    .map(String::from);
                Some(LockedDependency {
                    name: package_name_from_node_modules_path(path),
                    version,
                    resolved,
                })
            })
            .collect();
        return Ok(deps);
    }

    if let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) {
        let mut deps = Vec::new();
        collect_v1_dependencies(dependencies, &mut deps);
        return Ok(deps);
    }

    Ok(Vec::new())
}

fn package_name_from_node_modules_path(path: &str) -> String {
    path.rsplit("node_modules/")
        .next()
        .unwrap_or(path)
        .to_string()
}

fn collect_v1_dependencies(map: &serde_json::Map<String, Value>, out: &mut Vec<LockedDependency>) {
    for (name, entry) in map {
        if let Some(version) = entry.get("version").and_then(Value::as_str) {
            let resolved = entry
                .get("resolved")
                .and_then(Value::as_str)
                .map(String::from);
            out.push(LockedDependency {
                name: name.clone(),
                version: version.to_string(),
                resolved,
            });
        }
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            collect_v1_dependencies(nested, out);
        }
    }
}

/// Parse un `yarn.lock`, Classic (v1, `version "x.y.z"` + `resolved "url"`) et Berry
/// (v2+, `version: x.y.z`, pas d'URL `resolved` explicite). Le champ `version` précède
/// toujours `resolved` dans un bloc Classic : les dépendances en attente ne sont donc
/// poussées (avec leur `resolved`, si trouvé) qu'au bloc suivant ou en fin de fichier,
/// jamais dès la ligne `version`.
pub fn parse_yarn_lock(content: &str) -> Vec<LockedDependency> {
    let mut deps = Vec::new();
    let mut seen = HashSet::new();
    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if is_block_header(line) {
            flush_pending(
                &mut current_names,
                &mut current_version,
                None,
                &mut deps,
                &mut seen,
            );
            let header = line.trim_end_matches(':');
            current_names = header
                .split(',')
                .filter_map(|descriptor| package_name_from_descriptor(descriptor.trim()))
                .collect();
            continue;
        }

        if current_names.is_empty() {
            continue;
        }

        if let Some(version) = extract_version(line) {
            current_version = Some(version);
            continue;
        }

        if let Some(resolved) = extract_resolved(line) {
            flush_pending(
                &mut current_names,
                &mut current_version,
                Some(resolved),
                &mut deps,
                &mut seen,
            );
        }
    }
    flush_pending(
        &mut current_names,
        &mut current_version,
        None,
        &mut deps,
        &mut seen,
    );

    deps
}

fn flush_pending(
    names: &mut Vec<String>,
    version: &mut Option<String>,
    resolved: Option<String>,
    deps: &mut Vec<LockedDependency>,
    seen: &mut HashSet<LockedDependency>,
) {
    let Some(version) = version.take() else {
        names.clear();
        return;
    };
    for name in names.drain(..) {
        let dep = LockedDependency {
            name,
            version: version.clone(),
            resolved: resolved.clone(),
        };
        if seen.insert(dep.clone()) {
            deps.push(dep);
        }
    }
}

fn is_block_header(line: &str) -> bool {
    !line.starts_with(' ') && !line.starts_with('\t') && line.trim_end().ends_with(':')
}

fn package_name_from_descriptor(descriptor: &str) -> Option<String> {
    let trimmed = descriptor.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }
    let split_at = trimmed
        .match_indices('@')
        .map(|(index, _)| index)
        .rfind(|&index| index > 0)?;
    Some(trimmed[..split_at].to_string())
}

fn extract_version(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("version")?;
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    let value = rest.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.trim_matches('"').to_string())
}

fn extract_resolved(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("resolved")?;
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    let value = rest.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_lock_v1_including_nested_dependencies() {
        let content = r#"{
            "name": "demo",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": { "version": "4.17.21" },
                "@scope/pkg": {
                    "version": "1.0.0",
                    "dependencies": {
                        "nested-dep": { "version": "2.0.0" }
                    }
                }
            }
        }"#;

        let mut deps = parse_npm_lock(content).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(
            deps,
            vec![
                LockedDependency {
                    name: "@scope/pkg".into(),
                    version: "1.0.0".into(),
                    resolved: None,
                },
                LockedDependency {
                    name: "lodash".into(),
                    version: "4.17.21".into(),
                    resolved: None,
                },
                LockedDependency {
                    name: "nested-dep".into(),
                    version: "2.0.0".into(),
                    resolved: None,
                },
            ]
        );
    }

    #[test]
    fn parses_npm_lock_v3_flat_packages() {
        let content = r#"{
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "demo", "version": "1.0.0" },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                },
                "node_modules/@scope/pkg": { "version": "1.0.0" },
                "node_modules/@scope/pkg/node_modules/nested-dep": { "version": "2.0.0" }
            }
        }"#;

        let mut deps = parse_npm_lock(content).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(
            deps,
            vec![
                LockedDependency {
                    name: "@scope/pkg".into(),
                    version: "1.0.0".into(),
                    resolved: None,
                },
                LockedDependency {
                    name: "lodash".into(),
                    version: "4.17.21".into(),
                    resolved: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".into()),
                },
                LockedDependency {
                    name: "nested-dep".into(),
                    version: "2.0.0".into(),
                    resolved: None,
                },
            ]
        );
    }

    #[test]
    fn parses_yarn_classic_lockfile() {
        let content = concat!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n",
            "# yarn lockfile v1\n",
            "\n",
            "\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n",
            "  version \"7.12.3\"\n",
            "  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.12.3.tgz\"\n",
            "  dependencies:\n",
            "    \"@babel/code-frame\" \"^7.10.4\"\n",
            "\n",
            "lodash@^4.17.20:\n",
            "  version \"4.17.21\"\n",
            "  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n",
        );

        let mut deps = parse_yarn_lock(content);
        deps.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(
            deps,
            vec![
                LockedDependency {
                    name: "@babel/core".into(),
                    version: "7.12.3".into(),
                    resolved: Some(
                        "https://registry.yarnpkg.com/@babel/core/-/core-7.12.3.tgz".into()
                    ),
                },
                LockedDependency {
                    name: "lodash".into(),
                    version: "4.17.21".into(),
                    resolved: Some(
                        "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz".into()
                    ),
                },
            ]
        );
    }

    #[test]
    fn parses_yarn_berry_lockfile_and_ignores_metadata() {
        let content = concat!(
            "# This file is generated by running \"yarn install\".\n",
            "\n",
            "__metadata:\n",
            "  version: 6\n",
            "  cacheKey: 8\n",
            "\n",
            "\"@babel/core@npm:^7.12.3\":\n",
            "  version: 7.12.3\n",
            "  resolution: \"@babel/core@npm:7.12.3\"\n",
            "  dependencies:\n",
            "    \"@babel/code-frame\": ^7.10.4\n",
            "  languageName: node\n",
            "  linkType: hard\n",
            "\n",
            "\"lodash@npm:^4.17.20\":\n",
            "  version: 4.17.21\n",
            "  resolution: \"lodash@npm:4.17.21\"\n",
            "  languageName: node\n",
            "  linkType: hard\n",
        );

        let mut deps = parse_yarn_lock(content);
        deps.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(
            deps,
            vec![
                LockedDependency {
                    name: "@babel/core".into(),
                    version: "7.12.3".into(),
                    resolved: None,
                },
                LockedDependency {
                    name: "lodash".into(),
                    version: "4.17.21".into(),
                    resolved: None,
                },
            ]
        );
    }
}

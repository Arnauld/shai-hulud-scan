# test-data

Fixtures réelles (récupérées sur GitHub) pour garantir l'exhaustivité du parsing des
lockfiles npm/yarn (`src/lockfile.rs`) face aux formats et cas réels documentés dans
`specs.md` (SPEC-F04). Chaque sous-dossier contient un `package.json` et, selon le cas,
un `package-lock.json` ou un `yarn.lock` récupérés tels quels (aucune modification),
avec la provenance exacte ci-dessous pour permettre de re-télécharger la même version
si besoin.

## Fixtures

| Dossier | Source | Commit | Format couvert |
|---|---|---|---|
| `npm-v1-heroku-cra-node/` | [mars/heroku-cra-node](https://github.com/mars/heroku-cra-node) | `c414a25` | `package-lock.json` **`lockfileVersion: 1`** (npm v5/v6, arbre `dependencies` imbriqué, sans clé `packages`). |
| `npm-v2-bootstrap-npm-starter/` | [twbs/bootstrap-npm-starter](https://github.com/twbs/bootstrap-npm-starter) | `2258953` | `package-lock.json` **`lockfileVersion: 2`** (npm v7/v8, hybride `packages` + `dependencies` legacy). Contient **186** cas de dépendances transitives en conflit de version (`node_modules/<pkg>/node_modules/<dep>` imbriqué, ex. `node_modules/@babel/highlight/node_modules/chalk`) — cas de "télescopage" de version. |
| `npm-v3-vscode-helloworld-sample/` | [microsoft/vscode-extension-samples](https://github.com/microsoft/vscode-extension-samples) (`helloworld-sample/`) | `3d8442b` | `package-lock.json` **`lockfileVersion: 3`** (npm v9+, uniquement `packages`, plat). Contient 7 cas de dépendances transitives imbriquées. |
| `npm-v3-empty-stackblitz-node/` | [stackblitz/starters](https://github.com/stackblitz/starters) (`node/`) | `5f85544` | `package-lock.json` v3 **sans aucune dépendance** (uniquement l'entrée racine `""`) — cas limite : le parseur doit retourner une liste vide sans erreur. |
| `yarn-classic-serve-handler/` | [vercel/serve-handler](https://github.com/vercel/serve-handler) | `af11c99` | `yarn.lock` **Yarn Classic (v1)** (`# yarn lockfile v1`, syntaxe `version "x.y.z"`). |
| `yarn-berry-clipanion/` | [arcanis/clipanion](https://github.com/arcanis/clipanion) | `434b5a6` | `yarn.lock` **Yarn Berry (v2+)** (bloc `__metadata:`, syntaxe `version: x.y.z`, protocole `@npm:`). |
| `project-01/` | Projet Angular réel fourni par l'utilisateur (dépôt interne, non public) | — | `package-lock.json` **`lockfileVersion: 3`**, échelle réelle (**1160** paquets). Contient **207** cas de dépendances transitives en conflit de version (ex. `node_modules/@babel/core/node_modules/semver` vs la copie hissée). |

Récupérées le 2026-08-12 depuis la branche par défaut de chaque dépôt, à la révision
indiquée (`git log -1` équivalent au moment du téléchargement) :
```
mars/heroku-cra-node@c414a25250da57c73589163885e949e6f76c06e4
twbs/bootstrap-npm-starter@2258953be2d3bed2edfdee796aa7da9a550b3faf
microsoft/vscode-extension-samples@3d8442b16c7f353779e266f16295703b2b4a6dc
stackblitz/starters@5f855444c438cc9a08da1153a319c54bd570d2a9
vercel/serve-handler@af11c99f26a9b0b10780a4c7de1bde7ef16db1fb
arcanis/clipanion@434b5a6e0063c58b5e2f0a62498a7de0b308308f
```

## Résumé des spécifications de référence

Récupéré depuis la documentation officielle pour garantir que le parseur (`src/lockfile.rs`)
couvre bien tous les formats documentés, pas seulement les exemples ci-dessus.

### `package.json` ([docs.npmjs.com](https://docs.npmjs.com/cli/v10/configuring-npm/package-json))
- `name` + `version` : identifiant unique du paquet publié.
- `dependencies` / `devDependencies` / `peerDependencies` : associent un nom de paquet
  à un intervalle de version (`^1.2.3`, `~1.2`, `>=1.0.2 <2.1.2`, `1.2.x`, `*`,
  `range1 || range2`, URL git, chemin local, tarball...).
- `workspaces` : tableau de patterns de dossiers locaux (monorepo) — non géré
  spécifiquement par notre parseur, qui traite chaque `package.json` trouvé
  indépendamment (SPEC-F03 exclut déjà les `node_modules` des racines de projet).

### `package-lock.json` ([docs.npmjs.com](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json))
- **`lockfileVersion: 1`** (npm v5/v6) : uniquement une clé `dependencies`, arborescence
  imbriquée (chaque dépendance peut avoir ses propres `dependencies` transitives
  imbriquées récursivement). *Géré par `parse_npm_lock` (branche `dependencies`,
  `collect_v1_dependencies` récursif).*
- **`lockfileVersion: 2`** (npm v7/v8) : ajoute une clé `packages` (chemins
  `node_modules/<pkg>` à plat) tout en conservant `dependencies` en legacy pour la
  rétrocompatibilité. *Notre parseur préfère `packages` si présent (branche prioritaire
  dans `parse_npm_lock`), donc un fichier v2 est traité comme un v3 — comportement
  volontaire et suffisant puisque `packages` contient déjà toute l'information utile.*
- **`lockfileVersion: 3`** (npm v9+) : uniquement `packages`, format courant. *Géré par
  `parse_npm_lock` (branche `packages`, extraction du nom via
  `package_name_from_node_modules_path`, y compris paquets scopés et imbriqués).*

### `yarn.lock` Classic v1 ([classic.yarnpkg.com](https://classic.yarnpkg.com/lang/en/docs/yarn-lock/))
- En-tête `# yarn lockfile v1`, un bloc par résolution : un ou plusieurs descripteurs
  (`"pkg@^1.0.0", "pkg@^1.1.0":`) suivis de `version "x.y.z"` (guillemets, pas de `:`).
  *Géré par `parse_yarn_lock` / `extract_version` (variante sans `:`).*

### `yarn.lock` Berry v2+ (pas de spec formelle unique — confirmé via
[yarnpkg/berry#6042](https://github.com/yarnpkg/berry/issues/6042) et l'inspection de
fixtures réelles)
- Bloc `__metadata:` en tête (`version:`, `cacheKey:`) à ignorer — pas un paquet.
  *Géré : `package_name_from_descriptor("__metadata")` ne contient pas de `@`, donc
  ignoré naturellement sans cas spécial.*
- Résolutions au format `version: x.y.z` (avec `:`, souvent sans guillemets).
  *Géré par `extract_version` (variante avec `:`).*
- Protocole explicite dans le descripteur (`pkg@npm:^1.2.3`, `pkg@workspace:.`,
  `pkg@link:../local`) : notre extraction du nom (avant le dernier `@`) fonctionne
  quel que soit le protocole, y compris pour les paquets scopés
  (`@babel/core@npm:^7.12.3` → `@babel/core`).

## Utilisation

Ces fixtures sont consommées par les tests d'intégration de `tests/lockfile_fixtures.rs`
(`cargo test --test lockfile_fixtures`), en complément des cas synthétiques déjà
couverts par les tests unitaires de `src/lockfile.rs`. Chaque test parse une fixture
réelle et vérifie l'absence d'erreur ainsi que quelques dépendances attendues, y
compris le cas de conflit de version transitif (`ansi-styles` résolu à 3 versions
différentes dans `npm-v2-bootstrap-npm-starter/`).

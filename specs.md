# Spécifications Fonctionnelles et Techniques - Inspecteur de Sécurité Shai-Hulud (Rust)

Ce document définit les spécifications pour la réécriture et la généralisation en **Rust** de l'outil de diagnostic et d'audit de sécurité de l'espace de travail. L'objectif est d'obtenir un binaire unique, autonome, multi-plateforme, et à hautes performances, capable de mener à bien des analyses de sécurité approfondies.

---

## 🧭 Vision Architecturale
L'outil (baptisé de manière provisoire `shai-hulud-guard`) doit être conçu en Rust comme une CLI moderne, rapide et économe en mémoire. Il s'appuiera sur des bibliothèques de référence (crates) de l'écosystème Rust pour garantir l'asynchronisme, le parallélisme et des analyses de fichiers ultra-rapides.

Le code privilégiera le typage fort et devra être testable et documenté.

---

## 🛠️ Spécifications Fonctionnelles (SPEC-F)

### SPEC-F01 - Gestion de la base de signatures (IOC)
L'outil doit charger et exploiter la base de signatures d'attaques sous format CSV (provenant par exemple de Datadog Indicators of Compromise).

*   **Récupération Réseau :** Par défaut, tenter de télécharger la version la plus récente depuis l'URL
    officielle configurée par `official_ioc_url` dans `iocs.toml` (SPEC-T06, valeur par défaut
    embarquée : `https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/keyv-campaign/keyv-campaign/malicious-packages.csv`)
    — paramétrable sans recompilation via `--iocs-file`, distincte de `--database`/`--offline` qui
    concernent le fallback local, pas la source réseau.
*   **Résolution Locale & Fallback :** En cas d'absence de connexion réseau, utiliser un fichier local passé en argument (`--database <path>`) ou rechercher un fichier `malicious-packages.csv` présent dans le repertoire d'execution.
*   **Mode Forcé Hors-Ligne (`--offline`) :** Permettre de forcer l'utilisation de la base locale (`--database <path>` ou fichier trouvé dans le répertoire d'exécution) sans jamais tenter le téléchargement réseau, y compris lorsque celui-ci serait disponible. Utile pour les environnements CI/sandbox ou pour garantir l'usage d'une base de signatures figée/spécifique lors des tests.
*   **Format de Stockage en Mémoire :** Charger les signatures dans une structure de type `HashMap<String, Vec<String>>` où la clé est le nom du paquet NPM et la valeur est un tableau des versions compromises, optimisant ainsi les temps de recherche en $O(1)$.

Format du fichier CSV 

````csv
ecosystem,package,versions
npm,@adminide-stack/clock-tik-browser,12.0.24
npm,@adminide-stack/yantra-mobile,12.0.33
npm,@arv-bedrock/auth,1.1.7 | 1.1.8
npm,@arv-bedrock/auth-admin,1.0.2 | 1.0.3
npm,@arv-bedrock/auth-sso,1.6.1 | 1.6.2
npm,@arv-bedrock/auth-sso-backend,1.7.1 | 1.7.2
npm,@arv-bedrock/logger,1.7.1 | 1.7.2
npm,@cacheable/memory,2.2.1
npm,@cacheable/net,2.1.1
npm,@cacheable/node-cache,3.1.2
npm,@cacheable/utils,2.5.1
npm,@deliveroo/determinator,0.2.1
npm,@deliveroo/reevent,1.0.1
npm,@hubsync/web-sdk-react,6.3.7 | 6.3.8 | 6.3.9 | 6.3.10 | 6.3.11 | 6.3.12 | 6.3.13 | 6.3.14
````

### SPEC-F02 - Moteur de recherche et de parcours de fichiers ultra-rapide
Pour le parcours du système de fichiers, le binaire Rust doit s'affranchir des commandes système (`find`, `grep`, `rg`) afin de garantir une indépendance totale et des performances maximales, en particulier sur les systèmes de fichiers lents (ex. montages DrvFs / WSL `/mnt/c/`).
*   **Crate Recommandé :** Utiliser la crate **`ignore`** (le moteur de parcours parallèle derrière ripgrep). Elle gère nativement le multi-threading, respecte les fichiers `.gitignore`, filtre les dossiers cachés et permet d'élaguer très rapidement les arborescences géantes de dépendances.
*   **`--no-ignore` :** Flag CLI désactivant les règles `.gitignore`/`.ignore`/parent (mais pas
    le filtrage des dossiers cachés) pour la découverte de projets (SPEC-F03), l'audit des
    paquets déjà installés (SPEC-F04) et le scan passif (SPEC-F05/F08) — sans lui, un
    sous-dépôt intentionnellement ignoré (clone imbriqué, dépendance vendored...) est
    silencieusement absent de l'analyse.
*   **Fichiers cachés (`.env*`) :** Le scan passif (SPEC-F05/F08) a besoin de voir les
    dotfiles, élagués par défaut par la crate `ignore` — une variante de parcours dédiée
    inclut les fichiers/dossiers cachés (`.git/` reste exclu de la descente, jamais utile
    à inspecter, mais son chemin est capturé avant l'élagage — voir parcours unifié ci-dessous).
*   **Parcours unifié (`workspace::walk_workspace`) :** La découverte de projets (SPEC-F03), le
    scan passif (SPEC-F05/F08) et le repérage des dépôts `.git` (SPEC-F08 point 10) partagent
    **un seul** passage sur l'arborescence plutôt que trois parcours indépendants — coût
    significatif sur une racine sans `.gitignore` pour élaguer quoi que ce soit (`C:\`, `/`).
    Chaque entrée visitée est examinée par les deux traitements (est-ce un `package.json` hors
    `node_modules` ? le contenu contient-il un marqueur/une mention/un secret ?) ; les dossiers
    `.git` rencontrés sont collectés par leur chemin (capturé par le filtre d'élagage lui-même,
    sans coût de parcours supplémentaire) pour une analyse a posteriori
    (`hunt::scan_git_configs`), sans troisième parcours dédié. `discovery::discover` et
    `scan::scan_workspace` (leurs propres parcours indépendants) restent disponibles pour les
    tests unitaires en isolation, mais ne sont plus utilisés par le chemin de production.

voir https://github.com/BurntSushi/ripgrep/blob/master/Cargo.toml

### SPEC-F03 - Découverte hybride des projets (NPM et Yarn)
L'outil doit identifier de manière autonome les racines des projets JavaScript/Node.js :
*   **Répertoire de départ :** Le parcours récursif démarre à la racine passée en argument
    positionnel `[PATH]` (ex. `shai-hulud-guard /chemin/vers/workspace`). Ce répertoire sert
    à la fois de racine pour la découverte des projets (SPEC-F02/F03) et pour le Threat Hunting
    au niveau workspace (SPEC-F06/F07). Par défaut, en son absence, `PATH` vaut le répertoire
    courant d'exécution (`.`).
*   Rechercher récursivement tous les dossiers contenant un fichier `package.json`.
*   Détecter la présence concomitante de fichiers de verrouillage : `package-lock.json` (NPM) et `yarn.lock` (Yarn Classic ou Berry).
*   Générer un inventaire des projets trouvés sous forme de flux (Stream) envoyé au pool de travailleurs (Worker Pool).

### SPEC-F04 - Analyse double-niveau des Projets NPM/Yarn
Pour chaque dossier de projet Node.js identifié :

*   **Niveau 1 : Audit de l'existant :**
    *   Si un `package-lock.json` ou un `yarn.lock` existe, l'analyser.
    *   *NPM (JSON) :* Parser le fichier JSON et extraire les dépendances transitives des champs `packages` (formats v2/v3) et `dependencies` (format v1).
    *   *Yarn (Lockfile format) :* Écrire un décodeur linéaire efficace en Rust pour parser la syntaxe du `yarn.lock` (Classic v1 et Berry v2+) afin d'extraire les paquets et leurs versions résolues.
    *   Vérifier chaque dépendance par rapport à la base d'IOC et classifier en **trois** niveaux
        (et non plus une simple bascule vulnérable/sain) :
        *   `SAIN` : le paquet n'apparaît **pas du tout** dans la base IOC, quelle que soit la
            version rencontrée — totalement étranger à la campagne connue.
        *   `VULNÉRABLE` : le paquet **est référencé** dans la base IOC (au moins une version
            compromise y est connue), mais la version rencontrée ne correspond à **aucune** des
            versions listées — signal de vigilance sur un paquet ciblé par la campagne, sans
            confirmation exacte à cette version précise. Doit exposer la version rencontrée **et**
            la liste des versions compromises connues pour ce paquet, pour que l'utilisateur puisse
            juger de la proximité du risque.
        *   `CORROMPU` : la version rencontrée correspond **exactement** à une version listée comme
            compromise dans la base IOC — confirmation directe. Doit exposer la version rencontrée.
*   **Niveau 2 : Évaluation potentielle (Simulation), dans un répertoire de travail isolé :**
    *   **Ne jamais exécuter `npm install` dans le répertoire du projet lui-même.** Constaté en
        pratique : même en `--package-lock-only`, `npm` peut réécrire un `yarn.lock` déjà présent
        en effet de bord — une stratégie de sauvegarde/restauration `.orig` dans le répertoire
        d'origine reste donc intrinsèquement risquée (fenêtre de mutation, fichiers oubliés en cas
        de crash). La simulation doit s'exécuter dans une **copie isolée**, jamais dans l'arbre du
        projet scanné.
    *   **Répertoire de travail :** Au démarrage de l'outil, créer (si absent — ne jamais purger un
        répertoire préexistant à l'aveugle) un dossier `working/` dans le répertoire d'exécution
        courant (même convention que `malicious-packages.csv`, SPEC-F01).
    *   **Par simulation :** Créer sous `working/` un sous-répertoire temporaire dédié, nommé par le
        **SHA1 du chemin du fichier `package.json`** du projet (déterministe, sans collision entre
        projets). Le recréer proprement (purge + création) à chaque exécution pour garantir un état
        vierge, indépendamment de tout résidu d'un run précédent interrompu.
    *   **Copier uniquement les fichiers nécessaires à la génération** (`package.json` du projet)
        dans ce sous-répertoire — jamais le `package-lock.json`/`yarn.lock` d'origine, ni aucun
        autre fichier du projet.
    *   Lancer la commande de simulation NPM dans ce sous-répertoire isolé :
        ```bash
        npm install --package-lock-only --include=dev --ignore-scripts --audit=false --fund=false --legacy-peer-deps --no-workspaces
        ```
        *   **Flag Critique `--legacy-peer-deps` :** Indispensable pour contourner les erreurs de résolution de pairs (ERESOLVE) fréquentes sur les anciens dépôts, évitant ainsi un blocage de génération.
        *   **Flag Critique `--no-workspaces` :** Évite toute redirection vers un éventuel monorepo de workspaces au-dessus du répertoire ciblé (redondant avec l'isolation mais gardé par prudence).
    *   **Délai maximal (`--npm-timeout`, défaut 120s) :** La commande npm doit être bornée par un
        timeout. Sans cela, un seul projet dont la résolution réseau est lente, bloquée (registre
        privé, proxy, authentification manquante) ou qui boucle indéfiniment **bloque la totalité
        du scan** — y compris l'écriture du rapport final (`--report-file`/`--json`/console), qui
        n'a lieu qu'une fois toutes les simulations terminées. En cas de dépassement, abandonner ce
        projet (avertissement) et poursuivre le scan des autres projets.
    *   Analyser le `package-lock.json` potentiel généré **dans le sous-répertoire de travail**.
    *   Supprimer intégralement le sous-répertoire temporaire une fois l'analyse terminée, y compris
        en cas d'échec ou de timeout — le répertoire du projet original n'est, à aucun moment de ce
        niveau 2, ni modifié ni même ouvert en écriture.
    *   Enregistrer toutes les détections en mémoire de manière groupée.

> ⚠️ **`working/` ne doit jamais être traité comme du contenu à auditer** par le moteur de parcours
> (SPEC-F02), pour les mêmes raisons que `test-data/` ci-dessous : un résidu d'un run précédent
> interrompu (process tué en cours de simulation) contient un `package.json` copié qui serait sinon
> pris pour un vrai projet lors d'un run ultérieur.

> ⚠️ **Le workspace de développement de l'outil lui-même (`test-data/`, fixtures de test) ne doit
> jamais être traité comme un ensemble de projets à auditer** lorsque l'outil est lancé sur son
> propre dépôt ou un répertoire parent : cela déclencherait de vraies simulations `npm install`
> sur des fixtures statiques, avec les deux risques ci-dessus (mutation de fixture, blocage du
> scan). À exclure du moteur de parcours (SPEC-F02), indépendamment de tout suivi git.

### SPEC-F05 - Détection passive dans le code source (NPM et Yarn)
L'outil doit scanner le code source de tous les fichiers du dépôt (hors fichiers exclus : JSON
structurel, CSS, images, polices, archives) à la recherche d'occurrences d'instructions
d'installation directes.
*   **Crate Recommandé :** Utiliser la crate **`regex`** pour une recherche multi-threadée ultra-rapide.
*   **Regex NPM :** `npm\s(install|add|i|in|ins|inst|insta|instal|isnt|isnta|isntal|isntall|ci|clean-install|ic|install-clean|isntall-clean|update|u|up|upgrade|udpate)\b`
    — couvre `npm install`/`npm ci`/`npm update` **et** tous leurs alias documentés (`\b` final pour
    éviter qu'un alias court comme `i`/`u`/`up` ne matche par erreur le début d'un autre mot, ex.
    `npm inches`) :
    *   `install` : `add`, `i`, `in`, `ins`, `inst`, `insta`, `instal`, `isnt`, `isnta`, `isntal`,
        `isntall` (voir [npm-install](https://docs.npmjs.com/cli/v12/commands/npm-install)).
    *   `ci` : `clean-install`, `ic`, `install-clean`, `isntall-clean` (voir
        [npm-ci](https://docs.npmjs.com/cli/v12/commands/npm-ci)).
    *   `update` : `u`, `up`, `upgrade`, `udpate` (voir
        [npm-update](https://docs.npmjs.com/cli/v12/commands/npm-update)).
*   **Regex Yarn :** `yarn\s(install|add|ci|upgrade|run)`
*   **Nuance par contexte de commentaire (JS/JSX/TS/TSX/MJS/CJS/Python) :** `.js`/`.mjs`/`.cjs`
    ne sont plus exclus du scan — le risque de faux positif que cette exclusion visait à éviter
    (chaîne trouvée dans un commentaire, un exemple, ou la propre liste d'IOC d'un outil de
    sécurité) est désormais traité par un lexer de commentaires minimal (`comments.rs` : suit les
    chaînes `'...'`/`"..."`/`` `...` `` pour ne jamais confondre un `//` à l'intérieur d'une URL
    avec un commentaire, et les délimiteurs `//`, `/* */`, `#` eux-mêmes). Une correspondance
    (marqueur C2 SPEC-F08, mention npm/yarn install) trouvée **uniquement** à l'intérieur d'un
    commentaire :
    *   pour un marqueur C2 : reste un `ThreatSignal`, mais catégorisé
        `CommandFoundInComment` plutôt que `KnownC2Marker` — sévérité volontairement abaissée,
        toujours visible dans le rapport (transparence, SPEC-T05) mais distinguable d'une
        correspondance en code réellement exécuté.
    *   pour une mention npm/yarn install : n'est pas reportée du tout (déjà la sévérité la plus
        basse — simple indice contextuel, Debug uniquement — sans palier plus bas à modéliser).
    *   Les docstrings Python triple-guillemetées ne sont volontairement **pas** traitées comme
        des commentaires (distinction docstring/chaîne de donnée hors de portée d'un lexer sans
        contexte syntaxique) ; seuls les commentaires `#` classiques bénéficient de la nuance.

### SPEC-F06 - Recherche active de signaux malveillants (Threat Hunting / Forensics)
L'outil doit intégrer des fonctionnalités de détection de menaces actives sur la machine de l'utilisateur :

1.  **Vérification des Hooks de paquets installés (Grep `package.json` dans `node_modules`) :**
    *   *Optimisation requise :* Ne pas faire de parcours complet sur l'intégralité du disque pour node_modules. Cibler directement le dossier `<pkg_dir>/node_modules/*/package.json` pour chaque projet Node.js identifié afin d'obtenir un temps d'exécution en $O(1)$.
    *   *Comportement :* Parser ces fichiers à la recherche de la commande d'injection suspecte `"setup.mjs"`.
2.  **Fichiers suspects connus sur le disque :**
    *   Rechercher de manière foudroyante à la racine du workspace et aux racines de tous les projets la présence physique de fichiers nommés `"setup.mjs"` ou `"Math_Symbol.js"`.
3.  **Persistance macOS :**
    *   Rechercher la présence d'un LaunchAgent suspect contenant la chaîne de caractères `"gh-token-monitor"` dans le répertoire de persistance de l'utilisateur : `~/Library/LaunchAgents/`.

### SPEC-F07 - Détection étendue "Shai-Hulud 2.0 / The Second Coming" (vague Bun/TruffleHog)
Une seconde vague de la campagne (identifiée fin novembre 2025, alias `Sha1-Hulud`) utilise une chaîne d'infection différente, basée sur le runtime **Bun** et l'outil légitime **TruffleHog** détourné. Ces signaux doivent être ajoutés au moteur de Threat Hunting (SPEC-F06) :

1.  **Fichiers de charge utile (payload) sur le disque :**
    *   Rechercher, en plus de `setup.mjs` et `Math_Symbol.js`, les fichiers `setup_bun.js` et `bun_environment.js` (déclenchés via un script `preinstall` dans `package.json`).
    *   Rechercher un dossier de cache caché `.truffler-cache/` (utilisé pour dissimuler un binaire TruffleHog détourné).
2.  **Fichiers d'exfiltration générés localement (avant upload) :**
    *   Détecter la présence de `cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`, `actionsSecrets.json`, `data.json` à la racine des projets ou dans `/tmp` — ces fichiers regroupent les secrets collectés (clés cloud, tokens GitHub/npm) avant exfiltration.
3.  **Persistance CI/CD (GitHub Actions) :**
    *   Rechercher un fichier de workflow malveillant injecté dans `.github/workflows/` (noms observés : `shai-hulud-workflow.yml`, `discussion.yaml`).
    *   Signaler tout self-hosted runner GitHub nommé `SHA1HULUD` (visible via l'API GitHub, hors scope disque local mais à documenter comme signal complémentaire pour un futur mode `--check-github`).
4.  **Signature de dépôts d'exfiltration (si scan GitHub activé en option) :**
    *   Repérer les dépôts publics créés par le compte de la victime dont la description contient `"Shai-Hulud: The Second Coming"`, `"Shai-Hulud: Here We Go Again"` ou `"Shai-Hulud Migration"`.
5.  **Endpoint réseau connu (optionnel, mode réseau) :**
    *   Signaler toute occurrence de callback vers `webhook[.]site` dans du code source ou des logs, en particulier l'identifiant historique `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`.

> ⚠️ Ces IOC évoluent rapidement (nouvelles variantes régulièrement publiées par Datadog, JFrog, Wiz, Aikido, Socket.dev). L'outil doit permettre une mise à jour de la liste de fichiers/chaînes suspects sans recompilation (ex. fichier de configuration `iocs.toml` externe), plutôt que de figer ces valeurs en dur dans le binaire.

### SPEC-F08 - Détection étendue "CHAINDROP" (compromission `keyv` et paquets liés, source :
[Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain))
Une troisième vague documentée par Elastic (mainteneur `keyv` compromis — `keyv`, `flat-cache`,
`cacheable-request`, `cacheable`, `cache-manager`, 400+ paquets au total, 1,3 milliard de
téléchargements mensuels cumulés) introduit de nouveaux vecteurs à couvrir, en complément de
SPEC-F06/F07 :

1.  **Empreintes SHA-256 des charges connues :** En complément de la détection par nom, vérifier
    l'empreinte SHA-256 de tout fichier suspect trouvé sur le disque contre une liste de hashes
    connus — le ver renomme le fichier selon le vecteur de propagation en conservant un contenu
    identique, rendant le hash plus fiable que le nom seul :
    *   `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` (`Math_Symbol.js` **et**
        `math_init.js` — même hash, deux noms selon le vecteur de propagation).
    *   `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` (`setup.mjs`).
    *   `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` (`setup.mjs`, variante).
    *   Ajouter `math_init.js` et `bundle.js` aux noms de fichiers suspects connus (SPEC-F06).
    *   Une correspondance de hash est une confirmation directe (sévérité supérieure à une simple
        correspondance de nom, qui reste un indice).
2.  **Persistance Claude Code / VS Code (corrige un trou de couverture de SPEC-F06) :** Rechercher
    `.claude/setup.mjs` (déclenché par un hook `SessionStart` dans `.claude/settings.json`) et
    `.vscode/setup.mjs` (déclenché par une tâche `folderOpen` dans `.vscode/tasks.json`) — **pas
    seulement `<racine>/setup.mjs`** : ces sous-dossiers sont l'emplacement réel utilisé par la
    campagne, jusqu'ici absents du scan. Rechercher également `.dev-utils/server.js`.
3.  **Inventaire des scripts `preinstall`/`postinstall` :** Énumérer (pas seulement détecter par
    marqueur connu) tous les scripts `preinstall`/`postinstall` déclarés dans les `package.json`
    rencontrés (projets et `node_modules`), pour permettre l'inspection manuelle de chacun.
4.  **Chaînes C2 connues :** Recherche passive (SPEC-F05) des domaines/marqueurs C2 dans le code
    source : `npm-cache[.]com`, `awqhnjewqjkl[.]icu`, l'adresse du smart contract Ethereum
    `0xE1f2395ee43e45A1556EC6438a88c31B83493103` (résolveur de C2 dynamique — CHAINDROP ne code pas
    l'adresse en dur, il interroge ce contrat pour obtenir l'endpoint d'exfiltration courant), et
    les marqueurs de vagues précédentes (`js-mirror.com`, `pypi-get.com`, `SANDWORM`, `official334`,
    `webhook.site`).
5.  **Injection MCP dans Claude Code :** Vérifier `.claude/settings.json` et `.claude.json`
    (répertoire de config utilisateur Claude Code) pour la présence d'une clé `mcpServers`.
6.  **Persistance via hooks git :** Vérifier la configuration git (`init.templateDir`) et le
    contenu de `~/.git-templates/` pour des hooks suspects.
7.  **Détournement de registre :** Extraire le champ `resolved` des lockfiles npm/yarn (SPEC-F04)
    et signaler toute URL ne pointant pas vers un registre officiel attendu (`registry.npmjs.org`,
    `registry.yarnpkg.com`).
8.  **Exposition de secrets :** Vérifier `~/.npmrc` et les fichiers `.env*` du workspace pour la
    présence de jetons/secrets en clair.
9.  **Divergence lockfile / installé :** Comparer les versions déclarées dans le lockfile avec
    celles réellement présentes dans `node_modules`, signaler les paquets divergents.
10. **Identifiants en clair dans un remote git HTTP :** Pour chaque dépôt `.git` repéré par le
    parcours unifié du workspace (`workspace::walk_workspace`, SPEC-F02 — capturé au passage,
    sans jamais y descendre, sans parcours dédié), vérifier, pour chaque section `[remote "..."]`
    de son `config`, si l'URL déclarée utilise le
    protocole `http://` (non chiffré) **et** porte des identifiants en clair dans l'URL elle-même
    (userinfo `http://user:pass@host/...` ou `http://token@host/...`). Le secret trouvé n'est
    jamais reporté en clair dans le rapport (identifiants masqués, `http://***@host/...`) — même
    principe que le scan `.npmrc` (SPEC-F08 item 8), qui ne rapporte que le nom de la clé, jamais
    sa valeur. Portée volontairement limitée à `http://` : une URL `https://` avec des identifiants
    embarqués reste un mauvais usage (secret en clair sur disque), mais n'est pas transmise en
    clair sur le réseau — signal jugé moins prioritaire, non couvert ici.

> Prérequis d'exécution observé pour CHAINDROP : le jeton npm volé doit cumuler la permission
> d'écriture sur le paquet **et** `bypass_2fa` (publication sans 2FA) — information contextuelle,
> pas un signal détectable localement.

---

## ⚙️ Spécifications Techniques (SPEC-T)

### SPEC-T01 - Architecture asynchrone et parallélisée
*   **Runtime :** S'appuyer sur la crate **`tokio`** pour orchestrer le parallélisme.
*   **Worker Pool :** Utiliser un pool de threads pour paralléliser l'analyse des différents répertoires de projets.
*   **Limiteur de Concurrence (Sémaphore) :** Le lancement de processus lourds (`npm install`) doit être encadré par un sémaphore (`tokio::sync::Semaphore`) configurable (par exemple, 4 travailleurs max par défaut) pour éviter de saturer le disque ou les E/S du système, particulièrement sous WSL.

### SPEC-T02 - Indicateurs de progression et formats de sortie (CLI UX)
*   **Indicateur texte dédié (`progress::DotProgress`) :** Le parcours de fichiers (SPEC-F02) et la
    simulation `npm install` (SPEC-F04) affichent chacun un indicateur à deux niveaux : un point
    (`.`) ajouté sur la même ligne (stderr) tous les `batch_group` éléments traités (pas un par
    élément — trop bruyant sur de très grandes arborescences), puis un récapitulatif de la position
    tous les `batch_group * batch_group_limit` éléments, avec retour à la ligne (et un dernier
    récapitulatif en fin de flux). N'utilise **pas** la crate `indicatif` : sur certains terminaux
    Windows, sa gestion du curseur/redessin de ligne ne fonctionne pas correctement et produit une
    sortie illisible, entrecoupée des lignes de log — `DotProgress` ne dépend d'aucune fonctionnalité
    terminal au-delà d'un `print!`/flush basique, garanti de fonctionner partout, y compris en sortie
    redirigée. **Non désactivé par `--no-color`** : ce flag ne contrôle que les codes ANSI de
    couleur (console, rapport) — `DotProgress` n'en a jamais émis, les deux réglages sont
    indépendants.
*   **En-tête du rapport :** Chaque rapport (texte et JSON) commence par un en-tête `ReportHeader` —
    date/heure du scan (UTC, pas l'heure locale : la détection du fuseau local n'est pas fiable sur
    les binaires musl statiques minimaux, SPEC-T03) et nom + version de l'outil
    (`shai-hulud-guard <version>`, `CARGO_PKG_VERSION`) — utile pour tracer quand et avec quelle
    version un rapport archivé a été produit. Toujours affiché, quel que soit `--report-level`
    (métadonnée du rapport, pas du contenu filtrable par niveau).
*   **Formats de Restitution :**
    *   **Console :** Sortie interactive colorée avec des codes ANSI (pouvant être désactivée via `--no-color`).
    *   **Fichier Rapport :** Permettre l'écriture d'un rapport d'audit propre en texte brut via `--report-file <path>`, épuré de tout code ANSI.
    *   **Format Structuré JSON :** Option `--json` pour sortir les résultats sous forme d'un JSON structuré complet, facilitant l'intégration de l'outil dans des pipelines CI/CD ou d'autres outils de surveillance de sécurité.

### SPEC-T03 - Compilation et Déploiement multi-plateforme
L'outil doit compiler sous forme de binaire unique, statique et autonome, sans nécessiter l'installation préalable de runtime Python ou Node.js (bien qu'npm reste nécessaire pour l'étape de simulation SPEC-F04).
*   **Cibles d'export :**
    *   Linux (binaire statique compilé avec `x86_64-unknown-linux-musl` pour une portabilité totale sans dépendance `glibc`).
    *   macOS (binaire universel supportant Intel et Apple Silicon).
    *   Windows (binaire autonome `.exe`).

### SPEC-T04 - Journalisation (Logging)
L'outil doit intégrer une journalisation structurée, distincte des indicateurs de progression `DotProgress` (SPEC-T02) et du rapport d'audit final (console/`--report-file`/`--json`) : les logs sont un flux diagnostique séparé, pas une restitution des résultats.
*   **Crate Recommandée :** `tracing` + `tracing-subscriber`, cohérent avec l'architecture asynchrone `tokio` (SPEC-T01) et permettant d'instrumenter le cycle de vie de chaque étape (téléchargement IOC, parcours de fichiers, audit par projet, simulation npm, Threat Hunting) via des spans.
*   **Sortie :** Toujours sur **stderr**, jamais sur stdout, afin de ne jamais polluer une sortie `--json` redirigée dans un pipeline CI/CD. Respecte `--no-color` pour désactiver la coloration des logs comme celle du rapport.
*   **Niveaux :**
    *   `ERROR` : échec bloquant (ex. échec réseau **et** absence de fallback local pour la base IOC).
    *   `WARN` : échec partiel toléré (ex. simulation `npm install` échouée pour un projet, restauration du lockfile d'origine).
    *   `INFO` (niveau par défaut) : jalons de haut niveau, peu nombreux et non répétitifs (ex. lancement de l'analyse, base IOC chargée) — jamais un log par élément individuel (projet, dépendance, fichier), même sur un grand workspace.
    *   `DEBUG` : détail fin de chaque vérification (projet découvert, dépendance auditée, signal de Threat Hunting détecté, sortie brute des processus `npm install`).
*   **Mode Verbeux (`--verbose` / `-v`) :** Active le niveau `DEBUG` (uniquement pour ce binaire — les dépendances comme `ignore` restent à `INFO` pour éviter le bruit) et **journalise l'ensemble des fichiers analysés** lors du parcours (SPEC-F02), un log par fichier visité avec son chemin complet (ex. `fichier analysé : <path>`). Ce log par fichier reste désactivé par défaut (silencieux au niveau `INFO`) pour éviter un volume de sortie excessif sur de grandes arborescences.
*   **Isolation stricte console/logs :** Les processus externes lancés par l'outil (`npm install` en simulation, SPEC-F04) ne doivent **jamais** hériter des flux stdout/stderr du binaire — leur sortie est capturée et journalisée en `DEBUG`, jamais affichée directement sur la console.
*   **Répertoires/fichiers non traversés :** Toute entrée que le moteur de parcours (SPEC-F02) ne
    peut pas lire (permissions insuffisantes, chemin dépassant la limite historique `MAX_PATH` de
    Windows, boucle de symlinks...) doit être journalisée en `WARN`, **visible par défaut sans
    `--verbose`** — un scan qui semble "manquer" des dossiers sans explication est un défaut de
    diagnostic critique. Les exclusions volontaires (`.gitignore`/`.ignore`/fichiers cachés,
    décidées en interne par la crate de parcours) ne sont pas des erreurs : elles restent visibles
    via le pont `log` → `tracing` (la crate de parcours journalise ses propres décisions via la
    façade `log` standard) combiné à `--verbose`, qui active `DEBUG` pour cette crate en plus de
    `shai_hulud_guard`.
    *   **Cas "Accès refusé" simplifié :** Quand la cause est identifiable de façon fiable —
        `std::io::ErrorKind::PermissionDenied` (normalisé par la std lib depuis `EACCES` sur Unix et
        `ERROR_ACCESS_DENIED`/os error 5 sous Windows, très fréquent là-bas sur les dossiers système
        type `C:\Program Files\...`) — le message est raccourci au chemin concerné, sans le texte
        d'erreur OS verbeux répété à chaque entrée. Pour toute autre cause (chemin trop long, boucle
        de symlinks...), le message détaillé d'origine est conservé tel quel — ces cas ne se
        distinguent pas aussi proprement d'un simple `io::Error`.
*   **Fichier de log (`--log-file <path>`) :** En plus de stderr (jamais à sa place), écrire
    les logs dans le fichier indiqué, **toujours au niveau `DEBUG`** pour ce binaire —
    indépendamment de `--verbose`, qui ne contrôle que le niveau affiché sur la console. Objectif
    explicite : pouvoir suivre l'avancement d'un scan long (`tail -f <path>`) sans devoir choisir
    entre une console lisible et le détail complet, et sans attendre la fin du scan — contrairement
    au rapport final (`--report-file`/`--json`/console), qui n'est écrit qu'une seule fois, une fois
    **toutes** les simulations terminées, et ne doit donc jamais être confondu avec un fichier de
    log à surveiller en direct.
*   **Directives explicites (`--log-console-directive <directive>` / `--log-file-directive
    <directive>`) :** Permettent de fournir directement une directive de filtrage `tracing` (syntaxe
    `RUST_LOG`, ex. `"info,shai_hulud_guard=debug"`) pour, respectivement, la sortie console et le
    fichier de log, plutôt que de se limiter aux niveaux prédéfinis. Ordre de priorité pour la
    console : `RUST_LOG` (variable d'environnement) > `--log-console-directive` > `--verbose` — si
    `--log-console-directive` est fournie, elle **supplante** `--verbose`. Pour le fichier de log,
    `--log-file-directive` remplace la valeur par défaut (`"info,shai_hulud_guard=debug"`, toujours
    DEBUG) sans être affectée par `RUST_LOG` ni `--verbose` ; sans effet si `--log-file` n'est pas
    fourni.

### SPEC-T05 - Niveau de verbosité du rapport
Le rapport final (console et `--report-file`) doit exposer un niveau de détail configurable, **indépendant** du niveau de log `--verbose` (SPEC-T04) : par défaut, un utilisateur qui lance un scan de sécurité veut voir le résultat complet sans avoir à activer un mode diagnostique séparé.
*   **Flag CLI :** `--report-level <error|warn|info|debug>`, réutilisant la même échelle que la journalisation (SPEC-T04) plutôt qu'une taxonomie de verbosité ad hoc.
*   **Valeur par défaut : `debug`** (verbose) — volontairement l'inverse du niveau de log par défaut (`info`) : le bruit diagnostique doit rester discret par défaut, mais le résultat du scan doit être complet par défaut.
*   **Contenu par niveau (cumulatif, du plus restrictif au plus complet) :**
    *   `ERROR` : uniquement le récapitulatif des dépendances `CORROMPU`/`VULNÉRABLE` (SPEC-F04) et les signaux de Threat Hunting détectés (ou `"Aucune compromission détectée"` si le scan est propre) — jamais masqué, quel que soit le niveau choisi.
    *   `WARN` : ajoute le nombre total de dépendances analysées.
    *   `INFO` : ajoute le nombre de projets npm/yarn analysés.
    *   `DEBUG` (par défaut) : ajoute la liste complète des dépendances `SAIN`, pour une transparence totale sur tout ce qui a été vérifié.
*   **Récapitulatif groupé par projet :** L'outil doit conserver, pour chaque dépendance `VULNÉRABLE` ou `CORROMPU` détectée (SPEC-F04), le projet (chemin du dossier) qui la référence — au niveau 1 (lockfile), au niveau 2 (simulation), et pour les paquets déjà installés (`node_modules`). Le récapitulatif affiché **regroupe ces dépendances par projet** (un bloc par dossier de projet, trié par chemin), plutôt qu'une simple liste plate sans contexte : l'utilisateur doit pouvoir identifier immédiatement *quel* projet référence *quelle* version problématique.
*   **Portée :** S'applique uniquement au rendu texte (console et `--report-file`, tous deux dérivés du même rendu). Le format `--json` reste toujours complet (SPEC-T02), indépendamment de `--report-level`, puisqu'il est destiné à l'intégration programmatique et ne doit pas perdre d'information selon la verbosité choisie — chaque dépendance y porte déjà son projet d'origine.

### SPEC-T06 - Configuration externalisée des signatures IOC (`iocs.toml`)
Toutes les listes/valeurs de signatures utilisées par le moteur de Threat Hunting (SPEC-F06/F07/F08)
et le scan passif (SPEC-F05) doivent être paramétrables sans recompilation, plutôt que codées en dur
dans les modules Rust — ces signatures évoluent au rythme des campagnes, bien plus vite que le code
qui les consomme.
*   **Fichier embarqué par défaut :** `iocs.toml`, à la racine du dépôt, est intégré tel quel dans le
    binaire au moment de la compilation (`include_str!`) : aucun fichier n'est requis à côté de
    l'exécutable pour un fonctionnement par défaut complet.
*   **Flag CLI `--iocs-file <chemin>` :** fournit un fichier TOML personnalisé, **fusionné champ par
    champ** par-dessus les valeurs par défaut embarquées — toute clé absente du fichier fourni
    conserve sa valeur par défaut (un fichier qui ne redéfinit que `known_c2_markers`, par exemple,
    garde toutes les autres listes par défaut). Une clé présente mais explicitement vide (`[]`) vide
    bien la liste par défaut correspondante — la fusion ne s'applique qu'à l'absence de la clé, pas à
    son contenu. Distinct de `--database`/`--offline` (SPEC-F01), qui concernent le fallback CSV
    local des paquets npm compromis, pas les signatures de Threat Hunting — `official_ioc_url` fait
    toutefois exception : c'est l'URL réseau de cette même base CSV (SPEC-F01), mais elle vit dans ce
    fichier plutôt que dans le code pour la même raison que tout le reste ici (évolutivité sans
    recompilation).
*   **Valeurs paramétrables (toutes des listes, sauf les deux regex et l'URL) :** `suspicious_filenames`,
    `known_malicious_file_hashes` (liste de `{ hash, label }`), `suspicious_hook_markers`,
    `suspicious_launch_agent_markers`, `exfil_artifact_filenames`, `suspicious_workflow_filenames`,
    `suspicious_cache_dirnames`, `default_git_template_dirnames`, `npmrc_secret_keys`,
    `known_c2_markers`, `excluded_extensions`, `allowed_registry_hosts`, `npm_install_regex`,
    `yarn_install_regex`, `official_ioc_url` (SPEC-F01). Les marqueurs qui n'admettaient historiquement qu'une seule valeur en dur
    (hook VS Code/node_modules, LaunchAgent macOS, dossier de cache) sont désormais des listes,
    pour permettre d'en déclarer plusieurs.
*   **Alias npm/yarn :** paramétrés directement sous forme de regex complète (`npm_install_regex`/
    `yarn_install_regex`) plutôt que comme une liste d'alias assemblée en pattern au chargement — plus
    simple à auditer et à faire évoluer pour qui maintient ce fichier.
*   **Piège TOML à connaître :** une fois qu'un tableau de tables `[[known_malicious_file_hashes]]`
    est ouvert, toute ligne `clé = valeur` qui suit lui est rattachée plutôt que d'être une clé de
    premier niveau — cette section doit donc toujours rester en fin de fichier, après toutes les clés
    simples (voir l'avertissement en tête d'`iocs.toml`).
*   **Erreurs :** un fichier `--iocs-file` illisible, un TOML invalide, ou une regex `npm_install_regex`/
    `yarn_install_regex` invalide sont des erreurs bloquantes (échec net au démarrage, pas de repli
    silencieux) — un remplacement partiellement appliqué serait plus trompeur qu'un échec explicite.

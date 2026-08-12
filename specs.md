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

*   **Récupération Réseau :** Par défaut, tenter de télécharger la version la plus récente depuis l'URL officielle :
    `https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/keyv-campaign/keyv-campaign/malicious-packages.csv`
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
    *   Vérifier chaque dépendance par rapport à la base d'IOC et classifier : `VULNÉRABLE` (si version compromise détectée) ou `SAIN`.
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
L'outil doit scanner le code source de tous les fichiers du dépôt (hors fichiers exclus comme `.js`, `.json`, `.css`, images, binaires, etc.) à la recherche d'occurrences d'instructions d'installation directes.
*   **Crate Recommandé :** Utiliser la crate **`regex`** pour une recherche multi-threadée ultra-rapide.
*   **Regex NPM :** `npm\s(install|ci|update)`
*   **Regex Yarn :** `yarn\s(install|add|ci|upgrade|run)`

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

---

## ⚙️ Spécifications Techniques (SPEC-T)

### SPEC-T01 - Architecture asynchrone et parallélisée
*   **Runtime :** S'appuyer sur la crate **`tokio`** pour orchestrer le parallélisme.
*   **Worker Pool :** Utiliser un pool de threads pour paralléliser l'analyse des différents répertoires de projets.
*   **Limiteur de Concurrence (Sémaphore) :** Le lancement de processus lourds (`npm install`) doit être encadré par un sémaphore (`tokio::sync::Semaphore`) configurable (par exemple, 4 travailleurs max par défaut) pour éviter de saturer le disque ou les E/S du système, particulièrement sous WSL.

### SPEC-T02 - Indicateurs de progression et formats de sortie (CLI UX)
*   **Rapports Visuels :** Utiliser la crate **`indicatif`** pour afficher une barre de progression interactive et dynamique lors de la simulation npm et du parcours de fichiers.
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
L'outil doit intégrer une journalisation structurée, distincte des barres de progression `indicatif` (SPEC-T02) et du rapport d'audit final (console/`--report-file`/`--json`) : les logs sont un flux diagnostique séparé, pas une restitution des résultats.
*   **Crate Recommandée :** `tracing` + `tracing-subscriber`, cohérent avec l'architecture asynchrone `tokio` (SPEC-T01) et permettant d'instrumenter le cycle de vie de chaque étape (téléchargement IOC, parcours de fichiers, audit par projet, simulation npm, Threat Hunting) via des spans.
*   **Sortie :** Toujours sur **stderr**, jamais sur stdout, afin de ne jamais polluer une sortie `--json` redirigée dans un pipeline CI/CD. Respecte `--no-color` pour désactiver la coloration des logs comme celle du rapport.
*   **Niveaux :**
    *   `ERROR` : échec bloquant (ex. échec réseau **et** absence de fallback local pour la base IOC).
    *   `WARN` : échec partiel toléré (ex. simulation `npm install` échouée pour un projet, restauration du lockfile d'origine).
    *   `INFO` (niveau par défaut) : jalons de haut niveau, peu nombreux et non répétitifs (ex. lancement de l'analyse, base IOC chargée) — jamais un log par élément individuel (projet, dépendance, fichier), même sur un grand workspace.
    *   `DEBUG` : détail fin de chaque vérification (projet découvert, dépendance auditée, signal de Threat Hunting détecté, sortie brute des processus `npm install`).
*   **Mode Verbeux (`--verbose` / `-v`) :** Active le niveau `DEBUG` (uniquement pour ce binaire — les dépendances comme `ignore` restent à `INFO` pour éviter le bruit) et **journalise l'ensemble des fichiers analysés** lors du parcours (SPEC-F02), un log par fichier visité avec son chemin complet (ex. `fichier analysé : <path>`). Ce log par fichier reste désactivé par défaut (silencieux au niveau `INFO`) pour éviter un volume de sortie excessif sur de grandes arborescences.
*   **Isolation stricte console/logs :** Les processus externes lancés par l'outil (`npm install` en simulation, SPEC-F04) ne doivent **jamais** hériter des flux stdout/stderr du binaire — leur sortie est capturée et journalisée en `DEBUG`, jamais affichée directement sur la console.

### SPEC-T05 - Niveau de verbosité du rapport
Le rapport final (console et `--report-file`) doit exposer un niveau de détail configurable, **indépendant** du niveau de log `--verbose` (SPEC-T04) : par défaut, un utilisateur qui lance un scan de sécurité veut voir le résultat complet sans avoir à activer un mode diagnostique séparé.
*   **Flag CLI :** `--report-level <error|warn|info|debug>`, réutilisant la même échelle que la journalisation (SPEC-T04) plutôt qu'une taxonomie de verbosité ad hoc.
*   **Valeur par défaut : `debug`** (verbose) — volontairement l'inverse du niveau de log par défaut (`info`) : le bruit diagnostique doit rester discret par défaut, mais le résultat du scan doit être complet par défaut.
*   **Contenu par niveau (cumulatif, du plus restrictif au plus complet) :**
    *   `ERROR` : uniquement les dépendances `VULNÉRABLE` et les signaux de Threat Hunting détectés (ou `"Aucune compromission détectée"` si le scan est propre) — jamais masqué, quel que soit le niveau choisi.
    *   `WARN` : ajoute le nombre total de dépendances analysées.
    *   `INFO` : ajoute le nombre de projets npm/yarn analysés.
    *   `DEBUG` (par défaut) : ajoute la liste complète des dépendances `SAIN`, pour une transparence totale sur tout ce qui a été vérifié.
*   **Portée :** S'applique uniquement au rendu texte (console et `--report-file`, tous deux dérivés du même rendu). Le format `--json` reste toujours complet (SPEC-T02), indépendamment de `--report-level`, puisqu'il est destiné à l'intégration programmatique et ne doit pas perdre d'information selon la verbosité choisie.

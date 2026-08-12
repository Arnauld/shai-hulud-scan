# shai-hulud-guard

CLI Rust d'audit de sécurité détectant la compromission des dépôts npm/yarn par
le ver de supply-chain Shai-Hulud (et ses variantes). Binaire unique, statique,
multi-plateforme (Linux musl, macOS universal, Windows).

Spécifications complètes : [specs.md](./specs.md).

## Compilation

```bash
cargo build --release
```

Cibles cross-plateforme (Linux musl, macOS universal, Windows) : voir SPEC-T03 dans
[specs.md](./specs.md) et `scripts/build-macos-universal.sh`.

## Exemple de lancement

### Linux / macOS

```bash
./target/release/shai-hulud-guard /chemin/vers/workspace
```

### PowerShell (Windows)

```powershell
.\target\release\shai-hulud-guard.exe C:\chemin\vers\workspace
```

### Options courantes

```bash
./target/release/shai-hulud-guard \
  --offline --database malicious-packages.csv \
  --report-file scan-report.txt \
  --log-file scan-debug.log \
  --workers 4 \
  /chemin/vers/workspace
```

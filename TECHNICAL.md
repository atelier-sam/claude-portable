# Claude Code Portable — notes techniques

## Architecture

| Pièce | Rôle |
|---|---|
| `Claude.command` | Interface seule (bash + `gum`). Mac/Linux, et Windows via le bash de Git portable. |
| `lib/common.sh` | Plateforme, téléchargements vérifiés (fail-closed), mises à jour, purge de repli. |
| `core/` → `ccp-core` | Noyau Rust : comptes, identifiants, renouvellement, quotas, lancement verrouillé, outils Windows, accès distant. Contrat CLI versionné (`ccp-core --contract` = 1). |
| `claude.cmd` / `claude-classic.cmd` | Lanceurs Windows (wizard / repli 100 % batch). |
| `install.sh` / `install.ps1` / `uninstall.sh` | Installation depuis la release signée ; désinstallation. |
| `scripts/build-core.sh` | Compile `ccp-core` pour darwin-arm64/x64, linux-x64/arm64 (musl statique), win32-x64 (zig + cargo-zigbuild). |
| `scripts/release.sh` | Assemble la release à plat, `SHA256SUMS` signé, contre-vérifié avec la clé embarquée. |

Sans `ccp-core`, le wizard reste utilisable en mode dégradé (liste des comptes,
lancement direct, purge de repli).

## Comptes et identifiants

Chaque compte = un profil `config/<profil>/`, passé à Claude par `CLAUDE_CONFIG_DIR`.

- **macOS** : Claude range la session au Trousseau, service
  `Claude Code-credentials-<8 hex>` où les 8 hex = `sha256(NFC(CLAUDE_CONFIG_DIR))`.
  Un profil = un item. L'item **sans suffixe** est le Claude Code normal de la
  machine : `ccp-core` ne l'écrit ni ne le supprime jamais (lecture seule pour
  l'inventaire). Écriture par `security -i` (stdin) ; au-delà de 4 000 caractères,
  repli argv identique à celui de Claude (risque accepté, voir `creds/keychain.rs`).
- **Windows / Linux** : `config/<profil>/.credentials.json`.
- **Jeton longue durée** (`claude setup-token`) : `config/<profil>/oauth.token` ;
  quota illisible (403), forfait déclaré dans `config/<profil>/plan`.

**Jamais de copie d'identifiants entre magasins** : le refresh token tourne à chaque
renouvellement, la copie restante se fait révoquer. La réindexation fait donc une
connexion navigateur fraîche par compte (`accounts discover --missing`).

### Renouvellement

`POST platform.claude.com/v1/oauth/token`. Journal d'écriture anticipée
`.ccp-pending` posé AVANT l'écriture du magasin et rejoué au démarrage suivant :
un arrêt brutal entre « jeton obtenu » et « magasin écrit » ne perd rien (test qui
tue le processus à cet endroit). `invalid_grant` = état « à reconnecter », sans
boucle. Un seul renouvellement par 401.

### Statut, forfait, quota

`GET api.anthropic.com/api/oauth/profile` (forfait = `rate_limit_tier`) et
`/api/oauth/usage` (`anthropic-beta: oauth-2025-04-20`). Cache par profil
(300 s + gigue). Un 429 = `rate_limited` (limite par IP du point de statut, pas
un compte épuisé), dernières valeurs gardées. Recommandation : marge restante ×
multiplicateur (x20 = 20, x5 = 5, Pro = 1), seuil 95 %.

### Lancement

`ccp-core run <profil> --claude <bin> -- <args>` : verrou OS (`.ccp-session.lock`)
— un compte déjà ouvert renvoie le code 5 ; renouvellement préalable si besoin.

## Outils

- **Windows, logiciels** : `ccp-core win catalog` (embarqué, surchargeable par
  `config/catalog.toml`) puis `win install <clés>` → `winget install --id … -e
  --silent`, élévation demandée en amont, « déjà installé » = succès.
- **Windows, Office** : `win office --edition <clé> --lang fr-fr --apps …` →
  Office Deployment Tool, XML généré (`ExcludeApp` pour les apps non cochées,
  `AUTOACTIVATE=0`), ≥ 5 Go vérifiés, staging effacé.
- **Accès aux agents du Mac** : `remote connect` → `ssh` avec
  `ProxyCommand=cloudflared access ssh` vers `ssh-mac.atelier-sam.fr`
  (Cloudflare Access : code e-mail, 2 adresses autorisées, session 1 h), clé
  d'hôte du Mac pré-posée (`StrictHostKeyChecking=yes`), une seule connexion
  (liste des sessions tmux → choix → attache). `cloudflared` portable, version et
  empreintes épinglées.
- **Partage d'un PC Windows** (`remote share`, non éprouvé sur Windows) : sshd
  portable temporaire sur 127.0.0.1, clés seules, tunnel retour vers le Mac,
  Job Object kill-on-close, tout retiré à la sortie.
- **Côté Mac** (`remote setup-mac [--check]`) : sshd, LaunchAgent
  `fr.atelier-sam.ccp-mac-tunnel`, journal du tunnel, Access devant (302 sans
  bannière SSH), clé des agents restreinte `from="127.0.0.1,::1"`. Ne crée aucun
  objet Cloudflare (DNS / Access passent par l'API, hors binaire distribué).

## Poste invité

Le marqueur `config/.hosts/<hôte>` (`trusted` | `guest`) est demandé à la 1re
ouverture sur tout système. En quittant un poste `guest` : `accounts purge`
(Trousseau + identifiants en fichier, journal et sauvegardes) ; `remote` purge
aussi les jetons Cloudflare Access de cet hôte.

## exFAT, noexec

`chmod +x` puis test `--version` ; si le support est `noexec`, copie unique dans
`~/.cache/claude-portable/` et exécution de là (même règle pour `ccp-core`).

## Provenance des binaires

- Claude Code : `downloads.claude.ai/claude-code-releases/<version>/<plateforme>/claude[.exe]`,
  SHA256 du `manifest.json` (`platforms.<plat>.checksum`).
- `ccp-core`, wizard, lanceurs : release GitHub `atelier-sam/claude-portable`,
  `SHA256SUMS` signé `ccp-release` (clé publique dans `install.sh`, `install.ps1`,
  `lib/common.sh`).
- `gum` 0.17.0, `cloudflared` 2026.10.7, Win32-OpenSSH 10.4.0.0p1 : empreintes
  épinglées. Git for Windows : `digest` de l'API GitHub.

## Faire une release

```sh
scripts/build-core.sh && scripts/release.sh   # dist/release/ signé et contre-vérifié
```
Puis publier `dist/release/*` comme assets d'une release (Gitea, miroir GitHub :
les installeurs lisent `github.com/.../releases/latest/download/`).

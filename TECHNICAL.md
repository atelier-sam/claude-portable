# Claude Code Portable — notes techniques

Wrapper portable autour du **binaire natif officiel** de Claude Code
(`@anthropic-ai/claude-code`). Pas de Node.js : depuis la v2.x le binaire
`claude` est autonome (« the installed binary does not itself invoke Node »).

## Principe

| Aspect              | Choix                                                              |
|---------------------|--------------------------------------------------------------------|
| Runtime             | Binaire natif par plateforme, bucket officiel signé                |
| Node.js             | Inutile                                                            |
| Git (Windows)       | Git for Windows portable embarqué (`git-win/`) → outil Bash        |
| Git (Mac/Linux)     | Git système                                                        |
| Config + historique | `CLAUDE_CONFIG_DIR` → `config/<profil>/` sur la clé                 |
| **Auth**            | **`CLAUDE_CODE_OAUTH_TOKEN`** lu depuis `config/<profil>/oauth.token` |
| Token               | `claude setup-token` (long-lived), stocké **en clair** (pas de PIN)|
| Permissions         | `--dangerously-skip-permissions` + settings `bypassPermissions`    |
| Auto-update         | Désactivé (`DISABLE_AUTOUPDATER=1`) → MAJ via `UPDATE.*`            |

## Pourquoi le token en variable d'env (et pas le login natif)

Le login natif stocke la session dans `config/<profil>/.credentials.json`
(fichier) sur Windows/Linux → portable. **Mais sur macOS, Claude utilise le
Trousseau**, global par nom de service (pas par dossier config) : les profils
partageraient une connexion et le token ne serait pas porté sur la clé.

`CLAUDE_CODE_OAUTH_TOKEN` (conçu pour le headless/portable) **court-circuite le
Trousseau** et fonctionne identiquement sur Windows, macOS et Linux. C'est ce
qui garantit « je branche sur n'importe quel PC, je suis connecté ». Contrepartie :
le `/login` interne n'est plus le mécanisme de bascule (le token env prime) ; on
bascule de compte via les lanceurs `claude` / `claude1` (profils distincts).

## Profils

- `config/<profil>/oauth.token` — token long-lived (texte).
- `config/<profil>/` = `CLAUDE_CONFIG_DIR` (réglages + historique).
- `ACTIVE` (racine) — profil par défaut.
- Ajout de compte (menu → « a ») : lance `setup-token` sur un vrai TTY (jamais de
  capture `$(...)` : ça crashe le runtime), paste du token, validation `sk-ant-*`,
  écriture `config/<nom>/oauth.token`, fixe `ACTIVE`.

## Interface : un seul fichier-menu par OS

- **Windows** : `claude.cmd` — 100 % batch, AUCUN PowerShell (évite policy/BOM/version).
  Menu : lancer / choisir / ajouter (OAuth) / défaut / update / wipe. Double-clic OK.
  `.cmd` en CRLF obligatoire (LF casse `goto`). JAMAIS de BOM sur un `.cmd`.
- **Mac/Linux** : `Claude.command` — menu bash, source `lib/common.sh`.
- Le batch lit le token via `set /p VAR=<fichier`, exec direct du binaire. Pas de
  dépendance fragile. Logs auto à chaque run (`logs/`).

## Détection de plateforme

`uname` / `$env:PROCESSOR_ARCHITECTURE` → `darwin-arm64|x64`, `linux-x64|arm64`
(+`-musl` si Alpine), `win32-x64|arm64`. Jeu standard pré-téléchargé ; toute
plateforme manquante est récupérée au 1er lancement (self-heal, SHA256 vérifié).

## exFAT et bit d'exécution

Clé en exFAT (pas de `+x` persistant). Mac/Linux : `chmod +x` puis test
`--version` ; si la clé est montée `noexec`, copie unique du binaire dans
`~/.cache/claude-portable/<ver>/` et exécution de là. Windows : les `.exe`
s'exécutent sans bit d'exécution.

## Rotation multi-comptes « selon l'état »

Non fiable en usage **interactif** : un wrapper externe ne peut pas détecter
qu'un compte a atteint sa limite en cours de session TUI, ni basculer de compte
à chaud. Le réaliste : bascule manuelle `claude` ↔ `claude1`. La rotation
automatique (essayer compte B si A est rate-limited) n'a de sens qu'en
**headless** (`claude -p "…"`), où le wrapper voit le code de sortie / l'erreur
et peut relancer avec l'autre token. À ajouter sur demande.

## Sécurité — modèle de menace

- **Clé perdue/volée** : sans PIN, le token est directement exploitable →
  révoquer sur claude.ai (Réglages → applications connectées / tokens). `WIPE.*`
  efface tokens + sessions de la clé.
- **bypass permissions ON** : sur machine tierce, Claude agit sans confirmation.
- **Empreinte hôte** : config/historique restent sur la clé. Exception : cache
  binaire `~/.cache/claude-portable/` seulement si la clé est `noexec`.

## Provenance des binaires

- Claude Code : `https://downloads.claude.ai/claude-code-releases/<version>/<plateforme>/claude[.exe]`
  (SHA256 dans `manifest.json`, signé GPG par Anthropic).
- Git for Windows : release officielle `git-for-windows/git` (PortableGit 64-bit).

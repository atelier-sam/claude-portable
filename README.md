# Claude Code Portable

Claude Code officiel (binaire natif Anthropic) dans un **wizard de terminal** :
plusieurs comptes, **statut réel, forfait et quota 5 h / 7 j de chaque compte dès
l'accueil**, lancement du compte qui a le plus de marge, mode `bypass permissions`.
Plus des **outils d'atelier** : installation de logiciels Windows à cocher
(Office par version, LibreOffice, Chrome, Firefox, WinRAR…) et accès à tes agents
du Mac depuis le PC d'un client. Windows · macOS · Linux.

## Installer

**macOS / Linux**
```sh
curl -fsSL atelier-sam.fr/cc | bash
```

**Windows** (PowerShell)
```powershell
irm atelier-sam.fr/cc.ps1 | iex
```

Puis : `ccp` (wizard) — `ccp1` (2e compte).

Tout vient de la **dernière release signée** du dépôt : `SHA256SUMS` est signé
(`ssh-keygen -Y`, clé `ccp-release`), chaque fichier est vérifié avant d'être posé,
le binaire Claude est vérifié contre le manifest officiel d'Anthropic, `gum`,
Git portable et `cloudflared` contre des empreintes épinglées. Une seule
vérification ratée **arrête** l'installation.

## Ce que fait le wizard

- **Accueil** : un tableau par compte — email, forfait (Max x20 / x5 / Pro),
  quota 5 h et 7 jours, reprise, état (`valide`, `expiré`, `à reconnecter`,
  `limité`…). Les jetons expirés sont renouvelés seuls quand c'est possible.
- **Réindexer mes comptes** : retrouve les logins Claude déjà présents sur
  l'ordinateur et les reconnecte proprement dans le portable (une connexion
  navigateur par compte ; on ne copie jamais d'identifiants, une copie se fait
  révoquer). L'email connecté est vérifié.
- **Lancer le compte recommandé** (marge restante × forfait) ou un autre ; un
  compte déjà ouvert ailleurs n'est pas relancé.
- **Outils** — Windows : logiciels à cocher (winget, silencieux), Microsoft Office
  au choix (365, LTSC 2024/2021, Famille…) en français, sans clé (« non activé ») ;
  partager ce PC avec mes agents du Mac (temporaire). Partout : parler à mes agents
  du Mac (tunnel Cloudflare + code e-mail, puis mot de passe du Mac — rien
  d'installé sur le PC). macOS : vérifier ce Mac comme poste distant.
- **Mise à jour** de Claude (stable / dernière) avec retour arrière, et du portable.
- **Poste invité** : à la 1re ouverture, « cet ordinateur est-il à toi ? » ; si non,
  toutes les connexions sont effacées en quittant.

## Sécurité

Aucun secret dans ce dépôt ni dans les releases. Les sessions vivent sur la
machine : Trousseau macOS (un item par profil, jamais celui de ton Claude Code
normal) ou `~/.claude-portable/config/<compte>/` ailleurs. Quota et forfait sont
lus via les endpoints OAuth officiels avec le jeton du compte.

## Détails techniques

Voir [`TECHNICAL.md`](./TECHNICAL.md).

---
*L'Atelier de Sam — usage perso/atelier.*

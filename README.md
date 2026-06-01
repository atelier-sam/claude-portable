# Claude Code Portable

Claude Code officiel (binaire natif Anthropic) dans un **wizard de terminal** :
menu fléché, comptes multiples, statut connecté, **email + quota 5h/7j**, mode
`bypass permissions`. Fonctionne **sans installation** (depuis une clé USB) **ou**
en local via une commande courte. Windows · macOS · Linux.

## Installer (sans clé, en local)

**macOS / Linux**
```sh
curl -fsSL atelier-sam.fr/cc | bash
```

**Windows** (PowerShell)
```powershell
irm atelier-sam.fr/cc.ps1 | iex
```

Puis, partout :
```sh
ccp        # lance le wizard (compte actif)
ccp1       # 2e compte
```

L'installeur télécharge le binaire `claude` officiel + l'interface `gum`
(+ Git portable sous Windows) dans `~/.claude-portable`, et pose la commande `ccp`.

## Ce que fait le wizard

- Lancer / choisir un compte, en **ajouter** un (connexion navigateur ou import
  du compte de la machine), définir le compte par défaut.
- **Tableau** par compte : email, plan (Max/Pro), **quota 5h / 7 jours**, sessions.
- Mode `bypass permissions` activé par défaut.
- Mise à jour, effacement (kill switch).

## Sécurité

**Aucun secret dans ce dépôt.** Les tokens d'authentification vivent uniquement
en local dans `~/.claude-portable/config/<compte>/` (jamais commités — voir
`.gitignore`). L'installeur est lisible : tu peux l'auditer avant de l'exécuter.

Quota & email sont lus via les endpoints OAuth officiels (`/api/oauth/profile`,
`/api/oauth/usage`) avec le token du compte connecté, comme `claude --status`.

## Détails techniques

Voir [`TECHNICAL.md`](./TECHNICAL.md). Cœur partagé : `lib/common.sh` (détection
plateforme, téléchargement+vérif SHA256 du binaire, gum, quota). Wizard :
`Claude.command` (Mac/Linux, et Windows via le bash de Git portable). Lanceurs
Windows : `claude.cmd` (wizard) et `claude-classic.cmd` (repli 100 % batch).

---
*L'Atelier de Sam — usage perso/atelier.*

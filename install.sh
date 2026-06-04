#!/usr/bin/env bash
# ============================================================
#  Claude Code Portable — installeur macOS / Linux
#  Usage :  curl -fsSL atelier-sam.fr/cc | bash
#  Installe le wizard + le binaire Claude + gum dans ~/.claude-portable,
#  et la commande courte « ccp » (et « ccp1 » pour le 2e compte).
#  Aucun secret : tes tokens restent locaux dans ~/.claude-portable/config.
# ============================================================
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/atelier-sam/claude-portable/main"
DIR="${CLAUDE_PORTABLE_DIR:-$HOME/.claude-portable}"
BINDIR="$HOME/.local/bin"

say() { printf '\033[36m• %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m✓ %s\033[0m\n' "$*"; }

say "Installation de Claude Code Portable dans $DIR"
mkdir -p "$DIR/lib" "$BINDIR"

say "Récupération du wizard…"
curl -fsSL "$REPO_RAW/Claude.command" -o "$DIR/Claude.command"
curl -fsSL "$REPO_RAW/lib/common.sh"  -o "$DIR/lib/common.sh"
chmod +x "$DIR/Claude.command"

# Version (canal stable de Claude Code)
curl -fsSL "https://downloads.claude.ai/claude-code-releases/stable" -o "$DIR/VERSION" 2>/dev/null || echo stable > "$DIR/VERSION"

say "Téléchargement du binaire Claude + de l'interface (gum)… (peut prendre ~1 min)"
( ROOT="$DIR"; . "$DIR/lib/common.sh"; cc_detect_platform; cc_ensure_binary; cc_ensure_gum >/dev/null 2>&1 || true ) \
  || { printf '\033[31m✗ Échec du téléchargement des composants.\033[0m\n'; exit 1; }

# Commandes courtes
cat > "$BINDIR/ccp" <<EOF
#!/usr/bin/env bash
exec "$DIR/Claude.command" "\$@"
EOF
cat > "$BINDIR/ccp1" <<EOF
#!/usr/bin/env bash
exec env CC_PROFILE=2 "$DIR/Claude.command" "\$@"
EOF
chmod +x "$BINDIR/ccp" "$BINDIR/ccp1"
ok "Commandes installées : ccp  (et ccp1 pour le 2e compte)"

# PATH
case ":$PATH:" in
  *":$BINDIR:"*) ok "Tout est prêt. Tape :  ccp" ;;
  *)
    rc="$HOME/.zshrc"; [ -n "${BASH_VERSION:-}" ] && rc="$HOME/.bashrc"
    printf '\n\033[33m⚠ Ajoute %s à ton PATH :\033[0m\n' "$BINDIR"
    printf "   echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> %s && source %s\n" "$rc" "$rc"
    printf '\033[36mEnsuite, tape :  ccp\033[0m\n'
    ;;
esac

echo
say "Tout est rangé ici (tokens + sessions inclus) :  $DIR"
say "Effacer juste tes comptes : dans ccp -> « Tout déconnecter »."
say "Tout désinstaller (efface aussi le binaire) :"
printf '\033[2m   rm -rf %s %s/ccp %s/ccp1\033[0m\n' "$DIR" "$BINDIR" "$BINDIR"

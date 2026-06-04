#!/usr/bin/env bash
# ============================================================
#  Claude Code Portable — désinstallation / nettoyage des traces (thorough)
#  Usage :  curl -fsSL https://raw.githubusercontent.com/atelier-sam/claude-portable/main/uninstall.sh | bash
#  (ou, plus simple : rm -rf ~/.claude-portable ~/.local/bin/ccp ~/.local/bin/ccp1)
#  Supprime TOUT : binaire, interface, tokens + sessions, et l'item Trousseau macOS.
# ============================================================
set -uo pipefail
DIR="${CLAUDE_PORTABLE_DIR:-$HOME/.claude-portable}"
BINDIR="$HOME/.local/bin"

echo "Cela va supprimer :"
echo "  - $DIR   (binaire, interface, TOKENS + sessions)"
echo "  - $BINDIR/ccp  et  $BINDIR/ccp1"
printf "Confirmer ? [tape OUI] : "
read -r ans
[ "$ans" = "OUI" ] || { echo "Annulé."; exit 1; }

rm -rf "$DIR"
rm -f "$BINDIR/ccp" "$BINDIR/ccp1"

# macOS : Claude peut aussi avoir mis un credential dans le Trousseau lors d'un
# refresh. On tente de l'enlever (sans bloquer si absent).
if [ "$(uname -s)" = "Darwin" ]; then
  security delete-generic-password -s "Claude Code-credentials" >/dev/null 2>&1 || true
fi

echo "✓ Désinstallé. Plus aucune trace de Claude Code Portable sur cette machine."
echo "  (Pense à révoquer le token sur https://claude.ai si la machine n'est pas la tienne.)"

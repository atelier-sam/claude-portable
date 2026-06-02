#!/usr/bin/env bash
# ============================================================
#  Claude Code Portable — désinstallation / nettoyage des traces
#  Usage :  curl -fsSL atelier-sam.fr/cc-clean | bash
#  Supprime TOUT : binaire, interface, ET tokens + sessions.
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

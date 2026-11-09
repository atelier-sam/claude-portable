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

# macOS : chaque profil du portable a SA session dans le Trousseau, sous
# « Claude Code-credentials-<sha256(dossier config)[:8]> » (Claude suffixe le nom
# du service dès que CLAUDE_CONFIG_DIR est défini). On ne supprime QUE ces
# items-là, calculés depuis les dossiers de ce portable, AVANT d'effacer le
# dossier. Surtout pas « Claude Code-credentials » sans suffixe : c'est la
# session du Claude Code normal de la machine (~/.claude), pas la nôtre.
if [ "$(uname -s)" = "Darwin" ] && [ -d "$DIR/config" ]; then
  if [ -x "$DIR/bin/ccp-core" ]; then
    "$DIR/bin/ccp-core" --root "$DIR" accounts purge >/dev/null 2>&1 || true
  fi
  for d in "$DIR"/config/*/; do
    [ -d "$d" ] || continue
    cfg="${d%/}"
    svc="Claude Code-credentials-$(printf '%s' "$cfg" | shasum -a 256 | cut -c1-8)"
    security delete-generic-password -s "$svc" >/dev/null 2>&1 && echo "  - Trousseau : $svc supprimé"
  done
fi

rm -rf "$DIR"
rm -f "$BINDIR/ccp" "$BINDIR/ccp1"

echo "✓ Désinstallé. Plus aucune trace de Claude Code Portable sur cette machine."
echo "  (Pense à révoquer le token sur https://claude.ai si la machine n'est pas la tienne.)"

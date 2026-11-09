#!/usr/bin/env bash
# ============================================================
#  Claude Code Portable — installeur macOS / Linux
#  Usage :  curl -fsSL atelier-sam.fr/cc | bash
#  Installe le wizard + le noyau ccp-core + le binaire Claude + gum dans
#  ~/.claude-portable, et les commandes courtes « ccp » (et « ccp1 »).
#
#  Tout vient de la DERNIÈRE RELEASE SIGNÉE du dépôt (pas de la branche main) :
#  SHA256SUMS est signé (ssh-keygen -Y), chaque fichier est vérifié avant d'être
#  posé. Le binaire Claude est vérifié contre le manifest officiel d'Anthropic.
#  Aucun secret : tes sessions restent locales dans ~/.claude-portable/config.
# ============================================================
set -euo pipefail

# Surchargeable pour une recette locale : sans danger, la signature (clé ci-dessous) reste exigée.
CCP_DL="${CCP_DL:-https://github.com/atelier-sam/claude-portable/releases/latest/download}"
CCP_SIGNER='ccp-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINJP7f3uFSVRqxu997bLbJsDB+J8kerqZglqh5OH3PCS'
DIR="${CLAUDE_PORTABLE_DIR:-$HOME/.claude-portable}"
BINDIR="$HOME/.local/bin"

say() { printf '\033[36m• %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m✓ %s\033[0m\n' "$*"; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi; }

command -v curl >/dev/null 2>&1 || die "curl est requis."
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen est requis pour authentifier la release (paquet openssh-client)."

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
say "Installation de Claude Code Portable dans $DIR"

# 1) Sommes signées de la release
curl -fsSL "$CCP_DL/SHA256SUMS" -o "$W/SHA256SUMS" && curl -fsSL "$CCP_DL/SHA256SUMS.sig" -o "$W/SHA256SUMS.sig" \
  || die "Release injoignable (réseau ?)."
printf '%s\n' "$CCP_SIGNER" > "$W/allowed_signers"
ssh-keygen -Y verify -f "$W/allowed_signers" -I ccp-release -n file -s "$W/SHA256SUMS.sig" < "$W/SHA256SUMS" >/dev/null 2>&1 \
  || die "Signature de la release INVALIDE : installation annulée."
ok "Release authentifiée (signature ccp-release)"

# Télécharge un fichier de la release et le vérifie contre SHA256SUMS. $1 = nom publié, $2 = destination.
fetch() {
  local want
  want="$(awk -v n="$1" '$2==n || $2=="*"n {print $1; exit}' "$W/SHA256SUMS")"
  [ -n "$want" ] || die "$1 absent de la release."
  curl -fsSL "$CCP_DL/$1" -o "$W/$1" || die "Téléchargement de $1 échoué."
  [ "$(sha "$W/$1")" = "$want" ] || die "Empreinte invalide pour $1 : installation annulée."
  mkdir -p "$(dirname "$2")"; mv -f "$W/$1" "$2"
}

# 2) Wizard + bibliothèque, puis plateforme via la bibliothèque vérifiée
fetch Claude.command "$DIR/Claude.command"; chmod +x "$DIR/Claude.command"
fetch common.sh "$DIR/lib/common.sh"
ROOT="$DIR"
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
cc_detect_platform

# 3) Noyau ccp-core de cette plateforme
fetch "ccp-core-$CORE_PLAT" "$DIR/bin/$CORE_PLAT/ccp-core"; chmod +x "$DIR/bin/$CORE_PLAT/ccp-core"
ok "Wizard + noyau ccp-core vérifiés"

# 4) Claude (canal stable, vérifié contre le manifest Anthropic) + gum (empreinte épinglée)
curl -fsSL "https://downloads.claude.ai/claude-code-releases/stable" -o "$DIR/VERSION" || die "Version de Claude introuvable."
say "Téléchargement du binaire Claude + de l'interface… (peut prendre ~1 min)"
( set +e; cc_ensure_binary ) || die "Échec du téléchargement de Claude."
cc_ensure_gum >/dev/null 2>&1 || printf '\033[33m⚠ Interface gum indisponible : ccp lancera directement le compte par défaut.\033[0m\n'

# 5) Commandes courtes
mkdir -p "$BINDIR"
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

case ":$PATH:" in
  *":$BINDIR:"*) ok "Tout est prêt. Tape :  ccp" ;;
  *)
    rc="$HOME/.zshrc"; [ -n "${BASH_VERSION:-}" ] && [ "$(basename "${SHELL:-}")" = bash ] && rc="$HOME/.bashrc"
    printf '\n\033[33m⚠ Ajoute %s à ton PATH :\033[0m\n' "$BINDIR"
    printf "   echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> %s && source %s\n" "$rc" "$rc"
    printf '\033[36mEnsuite, tape :  ccp\033[0m\n'
    ;;
esac

echo
say "Tout est rangé ici (sessions incluses) :  $DIR"
say "Effacer juste tes comptes : dans ccp → « Tout déconnecter »."
say "Tout désinstaller (Trousseau compris) :  curl -fsSL https://raw.githubusercontent.com/atelier-sam/claude-portable/main/uninstall.sh | bash"

#!/usr/bin/env bash
# ============================================================
#  Assemble et SIGNE les fichiers d'une release du portable dans dist/release/.
#  Usage : scripts/build-core.sh && scripts/release.sh
#
#  Les installeurs (install.sh, install.ps1) et le wizard (cc_download_core,
#  cc_update_portable) ne posent un fichier QUE s'il figure dans SHA256SUMS et
#  que SHA256SUMS porte une signature valide de la clé « ccp-release ». Ce script
#  produit exactement cet ensemble, à plat (noms = ceux attendus par
#  `releases/latest/download/<nom>`), puis revérifie la signature avec la clé
#  publique EMBARQUÉE dans lib/common.sh : une release que les clients
#  refuseraient n'est jamais produite.
#
#  Clé privée : $CCP_SIGN_KEY (défaut ~/.ssh/ccp-release_ed25519 ; copie dans le
#  coffre : claude_portable.release_signing_key_ed25519). Jamais dans le dépôt.
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="${CCP_SIGN_KEY:-$HOME/.ssh/ccp-release_ed25519}"
OUT="$ROOT/dist/release"
die() { printf '✗ %s\n' "$*" >&2; exit 1; }

[ -f "$KEY" ] || die "clé de signature absente : $KEY"
signer="$(sed -n "s/^CCP_SIGNER='\(.*\)'$/\1/p" "$ROOT/lib/common.sh")"
[ -n "$signer" ] || die "CCP_SIGNER introuvable dans lib/common.sh"
# Les trois copies de la clé publique doivent être identiques.
for f in install.sh install.ps1; do
  grep -qF "${signer#ccp-release }" "$ROOT/$f" || die "clé publique de $f différente de lib/common.sh"
done

rm -rf "$OUT"; mkdir -p "$OUT"
cp "$ROOT/Claude.command" "$OUT/Claude.command"
cp "$ROOT/lib/common.sh" "$OUT/common.sh"
cp "$ROOT/claude.cmd" "$OUT/claude.cmd"
cp "$ROOT/claude-classic.cmd" "$OUT/claude-classic.cmd"
for plat in darwin-arm64 darwin-x64 linux-x64 linux-arm64 win32-x64; do
  exe=""; [ "$plat" = win32-x64 ] && exe=.exe
  src="$ROOT/dist/$plat/ccp-core$exe"
  [ -f "$src" ] || die "binaire manquant : $src (lancer scripts/build-core.sh)"
  cp "$src" "$OUT/ccp-core-$plat$exe"
done

( cd "$OUT" && shasum -a 256 -- * > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS )
ssh-keygen -q -Y sign -f "$KEY" -n file "$OUT/SHA256SUMS" >/dev/null
[ -f "$OUT/SHA256SUMS.sig" ] || die "signature non produite"

# Contre-vérification avec la clé publique embarquée (ce que fera chaque client).
printf '%s\n' "$signer" > "$OUT/.allowed_signers"
ssh-keygen -Y verify -f "$OUT/.allowed_signers" -I ccp-release -n file -s "$OUT/SHA256SUMS.sig" < "$OUT/SHA256SUMS" >/dev/null \
  || die "la signature produite ne se vérifie pas avec la clé embarquée"
rm -f "$OUT/.allowed_signers"
( cd "$OUT" && shasum -a 256 -c SHA256SUMS >/dev/null ) || die "SHA256SUMS incohérent"

printf '✓ Release signée dans %s :\n' "$OUT"
for f in "$OUT"/*; do printf "   %s\n" "${f##*/}"; done

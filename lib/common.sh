# shellcheck shell=bash
# shellcheck disable=SC2034  # BIN, CORE, CC_GUM, EXE… sont lus par Claude.command
# ============================================================
#  Bibliothèque partagée de Claude Code Portable (macOS / Linux / Windows-Git-bash).
#  Sourcée par Claude.command. Fixe ROOT avant de la sourcer.
#
#  Partage des rôles (cf TECHNICAL.md) :
#   - ce fichier : plateforme, téléchargements VÉRIFIÉS (claude, gum, ccp-core),
#     mises à jour + retour arrière, effacement ;
#   - ccp-core (Rust) : tout ce qui touche aux comptes (statut, Trousseau,
#     renouvellement, quota, lancement verrouillé). Le bash n'analyse aucun JSON.
#
#  Règle de sûreté : toute vérification qui ne peut pas conclure REFUSE
#  (fail-closed). Un binaire non vérifié ne s'exécute jamais.
# ============================================================

CC_RELEASES="https://downloads.claude.ai/claude-code-releases"
CCP_REPO="atelier-sam/claude-portable"
CCP_DL="${CCP_DL:-https://github.com/$CCP_REPO/releases/latest/download}"  # surcharge = recette locale ; signature toujours exigée
CCP_CONTRACT=1   # version du contrat CLI attendue de ccp-core (`ccp-core --contract`)

# Clé publique qui signe les SHA256SUMS des releases du portable
# (privée : coffre « claude_portable / release_signing_key_ed25519 »).
CCP_SIGNER='ccp-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINJP7f3uFSVRqxu997bLbJsDB+J8kerqZglqh5OH3PCS'

# gum épinglé : version + empreintes SHA256 relevées sur la release officielle
# (API GitHub, champ digest, 09/11/2026). Épingler évite de dépendre du réseau
# pour savoir quoi vérifier.
CC_GUM_VER="0.17.0"
cc_gum_sha() {
  case "$1" in
    Darwin_arm64)   echo e2a4b8596efa05821d8c58d0c1afbcd7ad1699ba69c689cc3ff23a4a99c8b237 ;;
    Darwin_x86_64)  echo cd66576aeebe6cd19c771863c7e8d696e0e1d5387d1e7075666baa67c2052e53 ;;
    Linux_arm64)    echo b0b9ed95cbf7c8b7073f17b9591811f5c001e33c7cfd066ca83ce8a07c576f9c ;;
    Linux_x86_64)   echo 69ee169bd6387331928864e94d47ed01ef649fbfe875baed1bbf27b5377a6fdb ;;
    Windows_x86_64) echo b2be80531c6babc8d4e0e6ca95773d58118a2e1582ae006aace08dbc55503072 ;;
    *) echo "" ;;
  esac
}

# Auto-updater désactivé : un binaire sur clé USB ne doit pas se réécrire depuis
# une machine cliente au hasard. Les MAJ passent par le menu, de façon contrôlée,
# avec retour arrière possible.
export DISABLE_AUTOUPDATER=1

# ─── Journal ────────────────────────────────────────────────────────────
# Toujours actif (logs/launch.log). Masque tout ce qui ressemble à un jeton :
# un journal sur clé USB ne doit jamais devenir une fuite.
cc_log() {
  local d="$ROOT/logs" line
  mkdir -p "$d" 2>/dev/null || true
  line="$(printf '%s' "$*" | sed -E 's/sk-ant-[A-Za-z0-9_-]+/sk-ant-<MASQUE>/g')"
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$line" >> "$d/launch.log" 2>/dev/null || true
}
cc_die()  { cc_log "ERREUR: $*"; printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
cc_info() { printf '\033[36m• %s\033[0m\n' "$*" >&2; }
cc_ok()   { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
cc_warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }

# ─── Plateforme ─────────────────────────────────────────────────────────
# PLAT = nom de plateforme des binaires Claude (darwin-arm64, linux-x64-musl…)
# CORE_PLAT = nom des binaires ccp-core (les linux sont en musl statique : un
# seul binaire par architecture, qui tourne aussi sur glibc).
cc_detect_platform() {
  local s m
  s="$(uname -s)"; m="$(uname -m)"
  case "$s" in
    Darwin) CC_OS=darwin ;;
    Linux)  CC_OS=linux ;;
    MINGW*|MSYS*|CYGWIN*) CC_OS=win32 ;;   # bash de Git for Windows
    *) cc_die "OS non supporté : $s" ;;
  esac
  case "$m" in
    arm64|aarch64) CC_ARCH=arm64 ;;
    x86_64|amd64|x86|i686) CC_ARCH=x64 ;;   # git-win est x64 (émulé sur ARM)
    *) cc_die "Architecture non supportée : $m" ;;
  esac
  PLAT="$CC_OS-$CC_ARCH"
  if [ "$CC_OS" = linux ]; then
    if ls /lib/ld-musl-* >/dev/null 2>&1 || ( command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl ); then
      PLAT="$PLAT-musl"
    fi
  fi
  CORE_PLAT="$CC_OS-$CC_ARCH"
  [ "$CC_OS" = win32 ] && CORE_PLAT=win32-x64   # un seul binaire Windows (ARM64 émule x64)
  BINNAME=claude; EXE=""
  [ "$CC_OS" = win32 ] && { BINNAME=claude.exe; EXE=".exe"; }
  # Claude Code sous Windows exige un bash de Git : on lui donne celui du portable.
  if [ "$CC_OS" = win32 ] && [ -f "$ROOT/git-win/bin/bash.exe" ]; then
    CLAUDE_CODE_GIT_BASH_PATH="$(cygpath -w "$ROOT/git-win/bin/bash.exe" 2>/dev/null)"
    export CLAUDE_CODE_GIT_BASH_PATH
  fi
}

# Convertit un chemin MSYS en chemin Windows pour les .exe natifs (claude.exe).
cc_winpath() {
  if [ "${CC_OS:-}" = win32 ]; then cygpath -w "$1" 2>/dev/null || printf '%s' "$1"
  else printf '%s' "$1"; fi
}

cc_sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo ""; fi
}

# Vérifie un fichier contre une empreinte attendue. Fail-closed : empreinte
# vide ou outil absent = refus.
cc_check_sha() {
  local f="$1" want="$2" got
  [ -n "$want" ] || { cc_warn "Empreinte attendue inconnue pour $(basename "$f") : refus."; return 1; }
  got="$(cc_sha256 "$f")"
  [ -n "$got" ] || { cc_warn "Aucun outil SHA256 (shasum/sha256sum) : refus."; return 1; }
  [ "$got" = "$want" ] || { cc_warn "Empreinte invalide pour $(basename "$f")."; return 1; }
}

# ─── Releases signées du portable ───────────────────────────────────────
# Télécharge SHA256SUMS + SHA256SUMS.sig de la dernière release et vérifie la
# signature (ssh-keygen -Y, présent sur macOS, Linux openssh et Git for Windows).
# $1 = dossier de travail. Écrit $1/SHA256SUMS vérifié. 0 si authentique.
cc_fetch_signed_sums() {
  local w="$1" sk
  sk="$(command -v ssh-keygen 2>/dev/null)"
  [ -n "$sk" ] || { cc_warn "ssh-keygen introuvable : impossible d'authentifier la release (refus)."; return 1; }
  curl -fsSL "$CCP_DL/SHA256SUMS" -o "$w/SHA256SUMS" && curl -fsSL "$CCP_DL/SHA256SUMS.sig" -o "$w/SHA256SUMS.sig" \
    || { cc_warn "Release du portable injoignable."; return 1; }
  printf '%s\n' "$CCP_SIGNER" > "$w/allowed_signers"
  "$sk" -Y verify -f "$w/allowed_signers" -I ccp-release -n file -s "$w/SHA256SUMS.sig" < "$w/SHA256SUMS" >/dev/null 2>&1 \
    || { cc_warn "Signature de la release INVALIDE : rien n'est installé."; return 1; }
}
# Empreinte d'un fichier listé dans un SHA256SUMS vérifié. $1 = SHA256SUMS, $2 = nom.
cc_sum_for() { awk -v n="$2" '$2==n || $2=="*"n {print $1; exit}' "$1"; }

# ─── Binaire Claude Code ────────────────────────────────────────────────
# Empreinte d'une plateforme dans le manifest officiel. Les objets plateforme du
# manifest n'ont pas d'accolade imbriquée (vérifié 09/11/2026), d'où le grep.
cc_manifest_sha() {
  printf '%s' "$1" | tr -d ' \n\t\r' | grep -o "\"$2\":{[^}]*}" | grep -o '"checksum":"[0-9a-f]*"' | head -1 | cut -d'"' -f4
}

# Télécharge le binaire d'une plateforme et vérifie le SHA256 du manifest officiel.
cc_download_binary() {
  local plat="$1" binname="$2" ver dir out manifest sha tmp
  ver="$(tr -d ' \r\n' < "$ROOT/VERSION" 2>/dev/null)"; [ -n "$ver" ] || ver=stable
  [ "$ver" = stable ] && ver="$(curl -fsSL "$CC_RELEASES/stable")"
  [ -n "$ver" ] || cc_die "Version de Claude introuvable (pas de réseau ?)"
  dir="$ROOT/bin/$plat"; mkdir -p "$dir"; out="$dir/$binname"; tmp="$dir/.$binname.part"
  cc_info "Téléchargement de Claude Code $ver pour $plat ..."
  manifest="$(curl -fsSL "$CC_RELEASES/$ver/manifest.json")" || cc_die "Manifest injoignable (pas de réseau ?)"
  sha="$(cc_manifest_sha "$manifest" "$plat")"
  curl -fsSL "$CC_RELEASES/$ver/$plat/$binname" -o "$tmp" || { rm -f "$tmp"; cc_die "Téléchargement échoué pour $plat"; }
  cc_check_sha "$tmp" "$sha" || { rm -f "$tmp"; cc_die "Binaire $plat non vérifié : refusé."; }
  mv -f "$tmp" "$out"; chmod +x "$out" 2>/dev/null || true
  printf '%s' "$ver" > "$ROOT/VERSION"
  cc_ok "Claude $ver ($plat) vérifié (SHA256 OK)"
}

# Rend exécutable un binaire du portable ; sur une clé exFAT montée noexec,
# copie unique dans le cache local de la machine. $1 = chemin, $2 = clé de cache.
# Écrit le chemin exécutable sur stdout.
cc_runnable() {
  local f="$1" key="$2" cache
  chmod +x "$f" 2>/dev/null || true
  if "$f" --version >/dev/null 2>&1; then printf '%s' "$f"; return 0; fi
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/claude-portable/$key"
  mkdir -p "$cache" 2>/dev/null || return 1
  if [ ! -x "$cache/$(basename "$f")" ] || ! cmp -s "$f" "$cache/$(basename "$f")"; then
    cc_info "Clé montée sans exécution : copie de $(basename "$f") en cache local ($cache)"
    cp "$f" "$cache/" && chmod +x "$cache/$(basename "$f")" || return 1
  fi
  "$cache/$(basename "$f")" --version >/dev/null 2>&1 || return 1
  printf '%s' "$cache/$(basename "$f")"
}

# Garantit un binaire Claude exécutable. -> BIN
cc_ensure_binary() {
  local raw="$ROOT/bin/$PLAT/$BINNAME" ver
  [ -f "$raw" ] || cc_download_binary "$PLAT" "$BINNAME"
  ver="$(tr -d ' \r\n' < "$ROOT/VERSION" 2>/dev/null || echo unknown)"
  BIN="$(cc_runnable "$raw" "$ver/$PLAT")" || cc_die "Impossible d'exécuter le binaire claude"
}

# Profil actif : variable CC_PROFILE > fichier ACTIVE > "1"
cc_active_profile() {
  if [ -n "${CC_PROFILE:-}" ]; then printf '%s' "$CC_PROFILE"
  elif [ -f "$ROOT/ACTIVE" ]; then tr -d ' \r\n' < "$ROOT/ACTIVE"
  else printf '1'; fi
}

# settings.json du profil (bypass permissions) + onboarding marqué fait.
cc_write_settings() {
  local cfg="$1"
  mkdir -p "$cfg"
  if [ ! -f "$cfg/settings.json" ]; then
    cat > "$cfg/settings.json" <<'JSON'
{
  "defaultMode": "bypassPermissions",
  "skipDangerousModePermissionPrompt": true,
  "env": {
    "DISABLE_AUTOUPDATER": "1"
  }
}
JSON
  fi
  [ -f "$cfg/.claude.json" ] || printf '{"hasCompletedOnboarding":true}\n' > "$cfg/.claude.json"
}

# ─── Interface gum ──────────────────────────────────────────────────────
cc_ensure_gum() {
  local g="$ROOT/tools/gum/$PLAT/gum$EXE" os arch tmp b asset
  CC_GUM="$g"
  [ -f "$g" ] && { chmod +x "$g" 2>/dev/null || true; return 0; }
  case "$CC_OS" in darwin) os=Darwin;; linux) os=Linux;; win32) os=Windows;; *) return 1;; esac
  case "$CC_ARCH" in arm64) arch=arm64;; x64) arch=x86_64;; *) return 1;; esac
  [ "$CC_OS" = win32 ] && arch=x86_64
  mkdir -p "$ROOT/tools/gum/$PLAT"
  tmp="$(mktemp -d)"
  cc_info "Téléchargement de l'interface gum ($CC_GUM_VER, $PLAT)…"
  if [ "$CC_OS" = win32 ]; then
    asset="gum_${CC_GUM_VER}_${os}_${arch}.zip"
    curl -fsSL "https://github.com/charmbracelet/gum/releases/download/v${CC_GUM_VER}/$asset" -o "$tmp/g.zip" \
      && cc_check_sha "$tmp/g.zip" "$(cc_gum_sha "${os}_${arch}")" \
      && ( cd "$ROOT/tools/gum/$PLAT" && unzip -o -j "$tmp/g.zip" '*gum.exe' >/dev/null 2>&1 )
  else
    asset="gum_${CC_GUM_VER}_${os}_${arch}.tar.gz"
    curl -fsSL "https://github.com/charmbracelet/gum/releases/download/v${CC_GUM_VER}/$asset" -o "$tmp/g.tgz" \
      && cc_check_sha "$tmp/g.tgz" "$(cc_gum_sha "${os}_${arch}")" \
      && tar xzf "$tmp/g.tgz" -C "$tmp" && b="$(find "$tmp" -type f -name gum | head -1)" && [ -n "$b" ] && cp "$b" "$g" && chmod +x "$g"
  fi
  rm -rf "$tmp"
  [ -f "$CC_GUM" ]
}

# ─── Noyau ccp-core ─────────────────────────────────────────────────────
# Télécharge (release signée) et valide le noyau. -> CORE (vide si indisponible :
# le wizard passe alors en mode dégradé, et LANCER fonctionne toujours).
cc_download_core() {
  local w name sha
  name="ccp-core-$CORE_PLAT$EXE"
  w="$(mktemp -d)" || return 1
  cc_info "Téléchargement du noyau ccp-core ($CORE_PLAT)…"
  if cc_fetch_signed_sums "$w" && curl -fsSL "$CCP_DL/$name" -o "$w/$name"; then
    sha="$(cc_sum_for "$w/SHA256SUMS" "$name")"
    if cc_check_sha "$w/$name" "$sha"; then
      mkdir -p "$ROOT/bin/$CORE_PLAT"
      mv -f "$w/$name" "$ROOT/bin/$CORE_PLAT/ccp-core$EXE"; chmod +x "$ROOT/bin/$CORE_PLAT/ccp-core$EXE" 2>/dev/null || true
      rm -rf "$w"; cc_ok "Noyau ccp-core vérifié (signature + SHA256)"; return 0
    fi
  fi
  rm -rf "$w"; return 1
}
cc_ensure_core() {
  local raw="$ROOT/bin/$CORE_PLAT/ccp-core$EXE" c
  CORE=""
  [ -f "$raw" ] || cc_download_core || { cc_log "ccp-core indisponible (téléchargement)"; return 1; }
  c="$(cc_runnable "$raw" "core/$CORE_PLAT")" || { cc_log "ccp-core non exécutable"; return 1; }
  if [ "$("$c" --contract 2>/dev/null | tr -d ' \r\n')" != "$CCP_CONTRACT" ]; then
    cc_log "ccp-core : contrat inattendu (attendu $CCP_CONTRACT)"; return 1
  fi
  CORE="$c"
}
# Appelle le noyau avec la racine du portable, Ctrl+C rendu à l'enfant (le
# wizard ignore SIGINT pour survivre à un Ctrl+C dans Claude).
ccp_core() { [ -n "${CORE:-}" ] || return 127; ( trap - INT; "$CORE" --root "$ROOT" "$@" ); }

# ─── Mises à jour ───────────────────────────────────────────────────────
# Dernière version stable de Claude, relevée au plus une fois par jour (bandeau
# « mise à jour disponible » de l'accueil). Écrit la version sur stdout.
cc_claude_stable_cached() {
  local f="$ROOT/.cache/claude-stable" now age v
  now="$(date +%s)"; mkdir -p "$ROOT/.cache" 2>/dev/null || true
  if [ -f "$f" ]; then age=$(( now - $(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0) )); else age=999999; fi
  if [ "$age" -gt 86400 ]; then
    v="$(curl -fsSL -m 4 "$CC_RELEASES/stable" 2>/dev/null | tr -d ' \r\n')"
    [ -n "$v" ] && printf '%s' "$v" > "$f"
  fi
  tr -d ' \r\n' < "$f" 2>/dev/null
}

# Met à jour le binaire Claude de CETTE plateforme (+ les autres présentes sur la
# clé), en gardant la version précédente (claude.prev) pour revenir en arrière.
# $1 = canal (stable/latest)
cc_update() {
  local channel="${1:-stable}" ver manifest plat binname sha tmp dst old here_ok=0
  local plats=()
  old="$(tr -d ' \r\n' < "$ROOT/VERSION" 2>/dev/null)"
  ver="$(curl -fsSL "$CC_RELEASES/$channel")" || { cc_warn "Pas de réseau."; return 1; }
  cc_info "Dernière version $channel : $ver (installée : ${old:-?})"
  manifest="$(curl -fsSL "$CC_RELEASES/$ver/manifest.json")" || { cc_warn "Manifest injoignable."; return 1; }
  for d in "$ROOT"/bin/*/; do
    [ -d "$d" ] || continue
    case "$(basename "$d")" in win32-*|darwin-*|linux-*) [ -f "$d/claude" ] || [ -f "$d/claude.exe" ] && plats+=("$(basename "$d")");; esac
  done
  [ "${#plats[@]}" -gt 0 ] || plats=("$PLAT")
  for plat in "${plats[@]}"; do
    binname=claude; case "$plat" in win32-*) binname=claude.exe ;; esac
    sha="$(cc_manifest_sha "$manifest" "$plat")"
    dst="$ROOT/bin/$plat/$binname"; tmp="$ROOT/bin/$plat/.$binname.new"
    cc_info "MAJ $plat ..."
    if curl -fsSL "$CC_RELEASES/$ver/$plat/$binname" -o "$tmp" && cc_check_sha "$tmp" "$sha"; then
      [ -f "$dst" ] && mv -f "$dst" "$dst.prev" && printf '%s' "${old:-?}" > "$ROOT/bin/$plat/.prev-version"
      if mv -f "$tmp" "$dst"; then
        chmod +x "$dst" 2>/dev/null || true; cc_ok "$plat à jour ($ver)"
        [ "$plat" = "$PLAT" ] && here_ok=1
      else
        # Remise en place de l'ancien binaire : jamais de plateforme sans claude.
        [ -f "$dst.prev" ] && [ ! -f "$dst" ] && mv -f "$dst.prev" "$dst"
        rm -f "$tmp"; cc_warn "$plat : installation impossible, ancienne version conservée."
      fi
    else rm -f "$tmp"; cc_warn "$plat : échec ou empreinte invalide, ancienne version conservée."; fi
  done
  # VERSION décrit le binaire de CETTE plateforme : on ne l'avance que s'il a
  # réellement été remplacé (sinon le bandeau « mise à jour disponible » disparaît
  # alors que l'ancien binaire tourne toujours).
  [ "$here_ok" = 1 ] || { cc_warn "Claude n'a pas été mis à jour sur $PLAT (version ${old:-?} conservée)."; return 1; }
  printf '%s' "$ver" > "$ROOT/VERSION"
  rm -f "$ROOT/.cache/claude-stable"
  cc_ok "Claude = $ver"
}

# Revient à la version précédente de Claude (celle gardée par cc_update).
cc_rollback() {
  local dst="$ROOT/bin/$PLAT/$BINNAME" prev
  [ -f "$dst.prev" ] || { cc_warn "Aucune version précédente gardée."; return 1; }
  prev="$(tr -d ' \r\n' < "$ROOT/bin/$PLAT/.prev-version" 2>/dev/null)"
  mv -f "$dst" "$dst.rollback-tmp" && mv -f "$dst.prev" "$dst" && mv -f "$dst.rollback-tmp" "$dst.prev"
  [ -n "$prev" ] && { printf '%s' "$(tr -d ' \r\n' < "$ROOT/VERSION")" > "$ROOT/bin/$PLAT/.prev-version"; printf '%s' "$prev" > "$ROOT/VERSION"; }
  cc_ok "Claude revenu à ${prev:-la version précédente}"
}

# Met à jour le portable lui-même (wizard, bibliothèque, lanceurs Windows, noyau)
# depuis la dernière release signée. Remplacement fichier par fichier, chacun
# vérifié AVANT d'écraser.
cc_update_portable() {
  local w f sha ok=0
  w="$(mktemp -d)" || return 1
  cc_fetch_signed_sums "$w" || { rm -rf "$w"; return 1; }
  for f in Claude.command lib/common.sh claude.cmd claude-classic.cmd "ccp-core-$CORE_PLAT$EXE"; do
    sha="$(cc_sum_for "$w/SHA256SUMS" "$(basename "$f")")"
    [ -n "$sha" ] || continue
    curl -fsSL "$CCP_DL/$(basename "$f")" -o "$w/$(basename "$f")" || { cc_warn "$(basename "$f") injoignable"; continue; }
    cc_check_sha "$w/$(basename "$f")" "$sha" || continue
    case "$f" in
      ccp-core-*) mkdir -p "$ROOT/bin/$CORE_PLAT"; mv -f "$w/$(basename "$f")" "$ROOT/bin/$CORE_PLAT/ccp-core$EXE"; chmod +x "$ROOT/bin/$CORE_PLAT/ccp-core$EXE" 2>/dev/null || true ;;
      *) mkdir -p "$ROOT/$(dirname "$f")"; mv -f "$w/$(basename "$f")" "$ROOT/$f" ;;
    esac
    ok=$((ok+1)); cc_ok "$(basename "$f") à jour"
  done
  chmod +x "$ROOT/Claude.command" 2>/dev/null || true
  rm -rf "$w"
  [ "$ok" -gt 0 ]
}

# ─── Effacement ─────────────────────────────────────────────────────────
# Efface les sessions de CE portable : Trousseau macOS (services suffixés
# seulement, jamais la session Claude Code normale de la machine) ET identifiants
# en fichier (seul magasin sous Windows/Linux). Passe par le noyau ; le repli
# bash couvre le cas « noyau absent », sinon un poste invité garderait tout.
# Rend 0 seulement si tout ce qui existait a été effacé.
# Code retour : 0 = tout effacé ; 2 = effacé mais une session ou un renouvellement
# encore vivant pourrait réécrire des identifiants (code 11 du noyau) ; 1 = échec.
cc_purge_sessions() {
  local core_rc=0
  ccp_core accounts purge >/dev/null 2>&1 || core_rc=$?
  case "$core_rc" in 0) return 0 ;; 11) return 2 ;; esac
  local d cfg f rc=0
  for d in "$ROOT"/config/*/; do
    [ -d "$d" ] || continue; cfg="${d%/}"
    if [ "${CC_OS:-}" = darwin ]; then
      security delete-generic-password -s "Claude Code-credentials-$(printf '%s' "$cfg" | shasum -a 256 | cut -c1-8)" >/dev/null 2>&1 || true
    fi
    # Même liste que core/src/purge.rs : journal, sa réservation (peut contenir
    # des jetons neufs) et les temporaires d'écriture atomique.
    for f in .credentials.json oauth.token oauth.token.bak .ccp-pending .ccp-pending.reserve "$cfg"/.ccp-tmp-*; do
      f="${f#"$cfg"/}"
      [ -e "$cfg/$f" ] || continue
      rm -f "$cfg/$f" 2>/dev/null || rc=1
      [ -e "$cfg/$f" ] && rc=1
    done
  done
  return "$rc"
}
# Ancien nom, gardé pour les appelants existants.
cc_purge_keychain() { cc_purge_sessions; }
# Efface toutes les sessions et jetons du portable (Trousseau compris).
cc_wipe() {
  cc_purge_keychain
  rm -rf "$ROOT"/config/* 2>/dev/null || true
  rm -f "$ROOT"/ACTIVE 2>/dev/null || true
}

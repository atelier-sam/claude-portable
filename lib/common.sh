# shellcheck shell=bash
# Bibliothèque partagée des lanceurs portables Claude Code (macOS / Linux).
# Sourcée par claude.sh, claude1.sh, account.sh, WIPE.sh, UPDATE.sh.
#
# Modèle d'auth : login natif par PROFIL (pas de token stocké, pas de PIN).
# Chaque profil = un dossier config/<profil>/ avec sa propre session Claude.
# Tu te connectes via le navigateur (au 1er lancement, ou avec /login). Sur
# Windows la session persiste dans config/ sur la clé (portable d'un PC à l'autre).

CC_RELEASES="https://downloads.claude.ai/claude-code-releases"

# Auto-updater désactivé : un binaire sur clé USB ne doit pas se réécrire depuis
# une machine cliente au hasard. Les MAJ passent par UPDATE.sh, de façon contrôlée.
export DISABLE_AUTOUPDATER=1

# Log automatique (toujours actif, aucune action requise) -> logs/launch.log
cc_log() {
  local d="$ROOT/logs"
  mkdir -p "$d" 2>/dev/null || true
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" >> "$d/launch.log" 2>/dev/null || true
}
cc_die()  { cc_log "ERREUR: $*"; printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
cc_info() { printf '\033[36m• %s\033[0m\n' "$*" >&2; }
cc_ok()   { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }

# Détecte os-arch -> PLAT (ex: darwin-arm64, linux-x64, linux-x64-musl)
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
  BINNAME=claude
  [ "$CC_OS" = win32 ] && BINNAME=claude.exe
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

# Télécharge le binaire d'une plateforme et vérifie le SHA256 vs manifest officiel.
cc_download_binary() {
  local plat="$1" binname="$2" ver dir out manifest sha got
  ver="$(cat "$ROOT/VERSION" 2>/dev/null || echo stable)"
  [ "$ver" = stable ] && ver="$(curl -fsSL "$CC_RELEASES/stable")"
  dir="$ROOT/bin/$plat"; mkdir -p "$dir"; out="$dir/$binname"
  cc_info "Téléchargement de Claude Code $ver pour $plat ..."
  manifest="$(curl -fsSL "$CC_RELEASES/$ver/manifest.json")" || cc_die "Manifest injoignable (pas de réseau ?)"
  sha="$(printf '%s' "$manifest" | tr -d ' \n\t' | grep -o "\"$plat\":{[^}]*}" | grep -o '"checksum":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
  curl -fsSL "$CC_RELEASES/$ver/$plat/$binname" -o "$out" || cc_die "Téléchargement échoué pour $plat"
  if [ -n "$sha" ]; then
    got="$(cc_sha256 "$out")"
    [ "$got" = "$sha" ] || { rm -f "$out"; cc_die "Checksum invalide pour $plat (attendu $sha)"; }
    cc_ok "Binaire $plat vérifié (SHA256 OK)"
  fi
  chmod +x "$out" 2>/dev/null || true
}

# Garantit un binaire exécutable ; gère exFAT (pas de +x persistant) via repli
# sur une copie en cache local de la machine. -> BIN
cc_ensure_binary() {
  BIN="$ROOT/bin/$PLAT/$BINNAME"
  [ -f "$BIN" ] || cc_download_binary "$PLAT" "$BINNAME"
  chmod +x "$BIN" 2>/dev/null || true
  if ! "$BIN" --version >/dev/null 2>&1; then
    local ver cache
    ver="$(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)"
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/claude-portable/$ver/$PLAT"
    mkdir -p "$cache"
    if [ ! -x "$cache/$BINNAME" ]; then
      cc_info "Système noexec sur la clé : copie du binaire en cache local ($cache)"
      cp "$BIN" "$cache/$BINNAME" && chmod +x "$cache/$BINNAME"
    fi
    BIN="$cache/$BINNAME"
    "$BIN" --version >/dev/null 2>&1 || cc_die "Impossible d'exécuter le binaire claude"
  fi
}

# Profil actif : variable CC_PROFILE > fichier ACTIVE > "1"
cc_active_profile() {
  if [ -n "${CC_PROFILE:-}" ]; then printf '%s' "$CC_PROFILE"
  elif [ -f "$ROOT/ACTIVE" ]; then tr -d ' \r\n' < "$ROOT/ACTIVE"
  else printf '1'; fi
}

# Charge le token portable du profil $1 (config/<profil>/oauth.token) dans
# CLAUDE_CODE_OAUTH_TOKEN. Ce token, posé une fois sur la clé, garantit la
# connexion sur N'IMPORTE QUEL PC / OS (ignore Trousseau macOS). 0 si chargé.
cc_load_token() {
  local tf="$ROOT/config/$1/oauth.token"
  [ -f "$tf" ] || return 1
  export CLAUDE_CODE_OAUTH_TOKEN="$(tr -d ' \r\n' < "$tf")"
  [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || { unset CLAUDE_CODE_OAUTH_TOKEN; return 1; }
  return 0
}

# Écrit settings.json (bypass permissions) si absent. $1 = config dir
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
  # Pré-marque l'onboarding comme fait → saute l'écran "Select login method"
  # au 1er lancement (le token est déjà fourni via .credentials.json).
  if [ ! -f "$cfg/.claude.json" ]; then
    printf '{"hasCompletedOnboarding":true}\n' > "$cfg/.claude.json"
  fi
}

# Met à jour les binaires présents (vérif SHA256 vs manifest). $1 = canal (stable/latest)
cc_update() {
  local channel="${1:-stable}" ver manifest plat binname sha tmp got
  local plats=()
  ver="$(curl -fsSL "$CC_RELEASES/$channel")" || { cc_info "Pas de réseau."; return 1; }
  cc_info "Dernière version $channel : $ver"
  manifest="$(curl -fsSL "$CC_RELEASES/$ver/manifest.json")" || { cc_info "Manifest injoignable."; return 1; }
  for d in "$ROOT"/bin/*/; do [ -d "$d" ] && plats+=("$(basename "$d")"); done
  [ "${#plats[@]}" -gt 0 ] || plats=(darwin-arm64 darwin-x64 linux-x64 linux-arm64 win32-x64 win32-arm64)
  for plat in "${plats[@]}"; do
    binname=claude; case "$plat" in win32-*) binname=claude.exe ;; esac
    sha="$(printf '%s' "$manifest" | tr -d ' \n\t' | grep -o "\"$plat\":{[^}]*}" | grep -o '"checksum":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
    [ -n "$sha" ] || continue
    mkdir -p "$ROOT/bin/$plat"; tmp="$ROOT/bin/$plat/.$binname.new"
    cc_info "MAJ $plat ..."
    if curl -fsSL "$CC_RELEASES/$ver/$plat/$binname" -o "$tmp"; then
      got="$(cc_sha256 "$tmp")"
      if [ "$got" = "$sha" ]; then mv -f "$tmp" "$ROOT/bin/$plat/$binname"; chmod +x "$ROOT/bin/$plat/$binname" 2>/dev/null || true; cc_ok "$plat à jour ($ver)"
      else rm -f "$tmp"; cc_info "✗ checksum $plat invalide, ancien conservé."; fi
    else rm -f "$tmp"; cc_info "✗ téléchargement $plat échoué."; fi
  done
  printf '%s' "$ver" > "$ROOT/VERSION"
  cc_ok "VERSION = $ver"
}

# ─── Quota / profil OAuth (méthode ai-cluster) ───────────────────────────
# Le token du login complet (.credentials.json, scope user:profile) permet :
#   GET /api/oauth/profile  → email, plan
#   GET /api/oauth/usage     → quota 5h / 7j (utilization %)
# On NE rafraîchit PAS le token nous-mêmes (Claude le maintient au lancement) :
# on lit le token courant ; s'il est expiré, on invite à lancer le compte.
CC_API="https://api.anthropic.com"
CC_BETA="oauth-2025-04-20"
CC_UA="claude-cli/portable"
CC_STATS_TTL=120

# Garantit la présence de gum (interface) pour la plateforme courante. -> CC_GUM
CC_GUM_VER="0.17.0"
cc_ensure_gum() {
  local g="$ROOT/tools/gum/$PLAT/gum"; [ "$CC_OS" = win32 ] && g="$g.exe"
  CC_GUM="$g"
  [ -f "$g" ] && { chmod +x "$g" 2>/dev/null || true; return 0; }
  local os arch tmp b
  case "$CC_OS" in darwin) os=Darwin;; linux) os=Linux;; win32) os=Windows;; *) return 1;; esac
  case "$CC_ARCH" in arm64) arch=arm64;; x64) arch=x86_64;; *) return 1;; esac
  mkdir -p "$ROOT/tools/gum/$PLAT"
  tmp="$(mktemp -d)"
  cc_info "Téléchargement de l'interface gum ($CC_GUM_VER, $PLAT)…"
  if [ "$CC_OS" = win32 ]; then
    curl -fsSL "https://github.com/charmbracelet/gum/releases/download/v${CC_GUM_VER}/gum_${CC_GUM_VER}_${os}_${arch}.zip" -o "$tmp/g.zip" \
      && ( cd "$ROOT/tools/gum/$PLAT" && unzip -o -j "$tmp/g.zip" '*gum.exe' >/dev/null 2>&1 )
  else
    curl -fsSL "https://github.com/charmbracelet/gum/releases/download/v${CC_GUM_VER}/gum_${CC_GUM_VER}_${os}_${arch}.tar.gz" -o "$tmp/g.tgz" \
      && tar xzf "$tmp/g.tgz" -C "$tmp" && b="$(find "$tmp" -type f -name gum | head -1)" && [ -n "$b" ] && cp "$b" "$g" && chmod +x "$g"
  fi
  rm -rf "$tmp"
  [ -f "$CC_GUM" ]
}

cc_cred_token() { grep -oE '"accessToken":"[^"]*"' "$ROOT/config/$1/.credentials.json" 2>/dev/null | head -1 | cut -d'"' -f4; }
cc_cred_exp()   { grep -oE '"expiresAt":[0-9]+'    "$ROOT/config/$1/.credentials.json" 2>/dev/null | head -1 | grep -oE '[0-9]+'; }
cc_has_login()  { [ -f "$ROOT/config/$1/.credentials.json" ]; }

# Récupère email/plan/quota et écrit config/<p>/.stats. Retour : 0 ok, 1 pas de
# login, 2 token expiré, 3 réseau/refus.
cc_fetch_stats() {
  local p="$1" at exp now prof usage email plan five seven
  cc_has_login "$p" || return 1
  at="$(cc_cred_token "$p")"; exp="$(cc_cred_exp "$p")"; now="$(( $(date +%s) * 1000 ))"
  [ -n "$at" ] || return 1
  if [ -n "$exp" ] && [ "$exp" -le "$now" ]; then return 2; fi
  prof="$(curl -s -m 8 "$CC_API/api/oauth/profile" -H "Authorization: Bearer $at" -H "anthropic-beta: $CC_BETA" -H "User-Agent: $CC_UA" 2>/dev/null)"
  usage="$(curl -s -m 8 "$CC_API/api/oauth/usage"   -H "Authorization: Bearer $at" -H "anthropic-beta: $CC_BETA" -H "User-Agent: $CC_UA" 2>/dev/null)"
  email="$(printf '%s' "$prof" | grep -oE '"email":"[^"]*"' | head -1 | cut -d'"' -f4)"
  if   printf '%s' "$prof" | grep -q '"has_claude_max":true'; then plan="Max"
  elif printf '%s' "$prof" | grep -q '"has_claude_pro":true'; then plan="Pro"
  else plan="?"; fi
  five="$(printf '%s'  "$usage" | grep -oE '"five_hour":\{"utilization":[0-9.]+'  | head -1 | grep -oE '[0-9.]+$' | cut -d. -f1)"
  seven="$(printf '%s' "$usage" | grep -oE '"seven_day":\{"utilization":[0-9.]+' | head -1 | grep -oE '[0-9.]+$' | cut -d. -f1)"
  [ -n "$email$five$seven" ] || return 3
  { echo "email=$email"; echo "plan=$plan"; echo "five=${five:-0}"; echo "seven=${seven:-0}"; echo "fetched=$(date +%s)"; } > "$ROOT/config/$p/.stats"
  return 0
}

cc_stats_get()   { grep -oE "^$2=.*" "$ROOT/config/$1/.stats" 2>/dev/null | head -1 | cut -d= -f2-; }
cc_stats_fresh() { local f; f="$(cc_stats_get "$1" fetched)"; [ -n "$f" ] || return 1; [ "$(( $(date +%s) - f ))" -lt "$CC_STATS_TTL" ]; }

# Efface tous les tokens + sessions de la clé.
cc_wipe() {
  rm -rf "$ROOT"/config/* 2>/dev/null || true
  rm -f "$ROOT"/ACTIVE 2>/dev/null || true
}

#!/usr/bin/env bash
# ============================================================
#  CLAUDE CODE PORTABLE — wizard Mac / Linux (interface gum)
#  Couleur Atelier de Sam (#D84D2B). Email + plan + quota 5h/7j
#  via le token du login complet (méthode ai-cluster).
# ============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$ROOT/lib/common.sh"
cc_detect_platform
# Le wizard ne doit pas mourir quand on fait Ctrl+C dans Claude (le signal va à
# tout le groupe). On l'ignore au niveau du menu : Claude gère son propre Ctrl+C,
# et on revient toujours à l'accueil. Quitter = via « Quitter ».
trap '' INT

cc_ensure_gum >/dev/null 2>&1 || true
GUMBIN="${CC_GUM:-$ROOT/tools/gum/$PLAT/gum}"
gum() { "$GUMBIN" "$@"; }

ORANGE="#D84D2B"; DG="244"; OK="42"; ERRC="203"
aO=$'\033[38;2;216;77;43m'; aOK=$'\033[38;2;70;170;100m'; aBAD=$'\033[38;2;205;70;55m'
aWARN=$'\033[38;2;230;160;60m'; aD=$'\033[2m'; aB=$'\033[1m'; aR=$'\033[0m'

cols() { local c; c=$(tput cols 2>/dev/null || echo "${COLUMNS:-80}"); case "$c" in ''|*[!0-9]*) c=80;; esac; echo "$c"; }
count_sessions() { find "$ROOT/config/$1/projects" -name '*.jsonl' ! -name '._*' 2>/dev/null | wc -l | tr -d ' '; }
count_projects() { find "$ROOT/config/$1/projects" -mindepth 1 -maxdepth 1 -type d ! -name '._*' 2>/dev/null | wc -l | tr -d ' '; }
free_space()     { df -h "$ROOT" 2>/dev/null | awk 'NR==2{print $4}'; }
install_size()   { du -sh "$ROOT" 2>/dev/null | awk '{print $1}'; }
plats_present()  { find "$ROOT/bin" -mindepth 1 -maxdepth 1 -type d ! -name '._*' 2>/dev/null | wc -l | tr -d ' '; }
os_label()       { case "$CC_OS" in darwin) echo macOS;; linux) echo Linux;; win32) echo Windows;; *) echo "$CC_OS";; esac; }
ver_str()        { tr -d ' \r\n' < "$ROOT/VERSION" 2>/dev/null || echo '?'; }
accounts()       { for d in "$ROOT"/config/*/; do [ -d "$d" ] || continue; n="$(basename "$d")"; case "$n" in ._*) continue;; esac; echo "$n"; done; }

# couleur d'une jauge selon le % utilisé
qcol() { local v="${1:-0}"; case "$v" in ''|*[!0-9]*) v=0;; esac; if [ "$v" -ge 80 ]; then printf '%s' "$aBAD"; elif [ "$v" -ge 50 ]; then printf '%s' "$aWARN"; else printf '%s' "$aOK"; fi; }

# Tableau en colonnes alignées (sans bordure : la police de Sam rend les
# box-drawing en pointillés). Montre Compte / Email / Plan / 5h / 7j / Sessions.
render_accounts() {
  local active n star email plan five seven sess c note any=0
  active="$(cc_active_profile)"
  c="$(cols)"
  printf '   %s%sCOMPTES%s\n' "$aB" "$aO" "$aR"
  if [ "$c" -ge 74 ]; then
    printf '   %s%-2s %-3s %-28s %-5s %-5s %-5s %-6s%s\n' "$aB" "" "Cpt" "Email" "Plan" "5h" "7j" "Sess." "$aR"
    while read -r n; do
      [ -n "$n" ] || continue; any=1
      [ "$n" = "$active" ] && star="${aO}★${aR}" || star=' '
      sess="$(count_sessions "$n")"
      if [ -f "$ROOT/config/$n/.stats" ]; then
        email="$(cc_stats_get "$n" email)"; plan="$(cc_stats_get "$n" plan)"
        five="$(cc_stats_get "$n" five)"; seven="$(cc_stats_get "$n" seven)"
        printf '   %b  %-3s %-28s %-5s %b%-5s%b %b%-5s%b %-6s\n' \
          "$star" "$n" "${email:0:28}" "${plan:-?}" \
          "$(qcol "$five")" "${five:-?}%" "$aR" "$(qcol "$seven")" "${seven:-?}%" "$aR" "$sess"
      else
        if cc_has_login "$n"; then note="a rafraichir"; elif [ -f "$ROOT/config/$n/oauth.token" ]; then note="a reconnecter"; else note="non connecte"; fi
        printf '   %b  %-3s %s%-28s%s %-5s %-5s %-5s %-6s\n' "$star" "$n" "$aD" "$note" "$aR" "-" "-" "-" "$sess"
      fi
    done <<< "$(accounts)"
  else
    # étroit : 2 lignes par compte
    while read -r n; do
      [ -n "$n" ] || continue; any=1
      [ "$n" = "$active" ] && star="${aO}★${aR}" || star=' '
      sess="$(count_sessions "$n")"
      if [ -f "$ROOT/config/$n/.stats" ]; then
        printf '   %b %-3s %s · %s\n' "$star" "$n" "$(cc_stats_get "$n" email)" "$(cc_stats_get "$n" plan)"
        printf '        %b5h %s%%%b · %b7j %s%%%b · %s sess\n' "$(qcol "$(cc_stats_get "$n" five)")" "$(cc_stats_get "$n" five)" "$aR" "$(qcol "$(cc_stats_get "$n" seven)")" "$(cc_stats_get "$n" seven)" "$aR" "$sess"
      else
        if cc_has_login "$n"; then note="à rafraîchir"; elif [ -f "$ROOT/config/$n/oauth.token" ]; then note="à reconnecter (Ajouter)"; else note="non connecté"; fi
        printf '   %b %-3s %s%s%s · %s sess\n' "$star" "$n" "$aD" "$note" "$aR" "$sess"
      fi
    done <<< "$(accounts)"
  fi
  [ "$any" = 1 ] || printf '     %s(aucun compte — choisis « Ajouter »)%s\n' "$aD" "$aR"
  # rappel si aucun compte n'a de quota
  if ! ls "$ROOT"/config/*/.stats >/dev/null 2>&1; then
    printf '   %s→ « — » = reconnecte le compte via « Ajouter » (login) pour email + quota%s\n' "$aD" "$aR"
  fi
}

totals_line() {
  local nb=0 conn=0 tot=0 n
  while read -r n; do [ -n "$n" ] || continue; nb=$((nb+1)); { cc_has_login "$n" || [ -f "$ROOT/config/$n/oauth.token" ]; } && conn=$((conn+1)); tot=$((tot+$(count_sessions "$n"))); done <<< "$(accounts)"
  printf '   %s%s compte(s) · %s connecté(s) · %s sessions au total%s\n' "$aD" "$nb" "$conn" "$tot" "$aR"
}

render() {
  clear 2>/dev/null || true
  local c pw status
  c="$(cols)"; pw=$((c-6)); [ "$pw" -gt 72 ] && pw=72; [ "$pw" -lt 24 ] && pw=24
  if [ "$c" -ge 54 ]; then status="v$(ver_str) · $(os_label) ($PLAT) · $(free_space) libres · bypass ON"
  else status="v$(ver_str) · bypass ON"; fi
  gum style --width "$pw" --border rounded --border-foreground "$ORANGE" --padding "0 2" --margin "1 0 1 2" --align center --foreground "$ORANGE" --bold \
    "CLAUDE CODE PORTABLE" "$(gum style --foreground "$DG" --faint "$status")"
  render_accounts
  echo; totals_line; echo
}

refresh_all_stats() { local n; while read -r n; do [ -n "$n" ] || continue; cc_has_login "$n" && cc_fetch_stats "$n" >/dev/null 2>&1; done <<< "$(accounts)"; }

# ---------- actions ----------
launch() {
  clear 2>/dev/null || true
  local p="$1"; [ -n "$p" ] || p="$(cc_active_profile)"
  cc_log "=== lancement profil=$p ==="
  local cfg="$ROOT/config/$p"; cc_write_settings "$cfg"; export CLAUDE_CONFIG_DIR="$(cc_winpath "$cfg")"
  unset CLAUDE_CODE_OAUTH_TOKEN
  if cc_has_login "$p"; then cc_log "login (.credentials.json)"
  elif cc_load_token "$p"; then cc_log "token simple (env)"
  else gum style --foreground "$ERRC" --margin "0 0 0 3" "⚠  Compte « $p » non connecté — « Ajouter »."; fi
  gum style --foreground "$ORANGE" --bold --margin "1 0 1 3" "▶  Compte « $p » — bypass ON — démarrage…   (/status dans Claude = vue native)"
  "$BIN" --dangerously-skip-permissions || true
  cc_log "claude terminé"
  cc_has_login "$p" && cc_fetch_stats "$p" >/dev/null 2>&1 || true
}

choose_account() {
  local list; list="$(accounts)"
  [ -n "$list" ] || { gum style --foreground "$ERRC" "Aucun compte. Ajoute-en un d'abord."; sleep 1; return 1; }
  printf '%s\n' "$list" | gum choose --header "Quel compte lancer ?" --cursor "❯ " --cursor.foreground "$ORANGE"
}

add_account() {
  clear 2>/dev/null || true
  local name
  gum style --border rounded --border-foreground "$ORANGE" --padding "0 2" --margin "1 0 1 2" --foreground "$ORANGE" --bold "AJOUTER / RECONNECTER UN COMPTE"
  name="$(gum input --header "Nom du compte (ex: 1, 2, perso)" --placeholder "1" --cursor.foreground "$ORANGE")" || return
  [ -n "$name" ] || return
  case "$name" in *[!a-zA-Z0-9_-]*) gum style --foreground "$ERRC" "Nom invalide."; sleep 1; return;; esac
  mkdir -p "$ROOT/config/$name"; cc_write_settings "$ROOT/config/$name"
  local method
  method="$(gum choose --header "Comment connecter « $name » ?" --cursor "❯ " --cursor.foreground "$ORANGE" \
    "Nouvelle connexion navigateur (recommandé — token longue durée)" \
    "Importer le compte de cet ordinateur (rapide mais expire ~8h)")" || return
  case "$method" in
    Importer*)
      if [ -f "$HOME/.claude/.credentials.json" ]; then
        cp "$HOME/.claude/.credentials.json" "$ROOT/config/$name/.credentials.json"
        chmod 600 "$ROOT/config/$name/.credentials.json" 2>/dev/null || true
        gum style --foreground "$OK" --margin "1 0 0 2" "Compte de cette machine importé."
      else
        gum style --foreground "$ERRC" --margin "1 0 0 2" "Aucun compte connecté ici (~/.claude). Lance Claude/login une fois, ou choisis « Nouvelle connexion »."
        sleep 2; return
      fi ;;
    *)
      gum style --foreground "$DG" --margin "1 0 1 2" "Une page de connexion va s'ouvrir. Connecte-toi au compte voulu."
      CLAUDE_CONFIG_DIR="$(cc_winpath "$ROOT/config/$name")" "$BIN" auth login || gum style --foreground "$ERRC" "Login interrompu."
      # Repli (surtout macOS où le login va dans le Trousseau) : importer le login machine.
      cc_has_login "$name" || { [ -f "$HOME/.claude/.credentials.json" ] && cp "$HOME/.claude/.credentials.json" "$ROOT/config/$name/.credentials.json"; }
      ;;
  esac
  rm -f "$ROOT/config/$name/oauth.token" 2>/dev/null
  printf '%s' "$name" > "$ROOT/ACTIVE"
  if cc_has_login "$name"; then
    gum style --foreground "$DG" --margin "1 0 0 2" "Récupération du compte + quota…"
    cc_fetch_stats "$name" >/dev/null 2>&1 || true
    gum style --foreground "$OK" --bold --margin "0 0 0 2" "✓ Compte « $name » connecté : $(cc_stats_get "$name" email) ($(cc_stats_get "$name" plan))"
  else
    gum style --foreground 214 --margin "1 0 0 2" "Login non détecté dans config/ (le Trousseau Mac a pu être utilisé — dis-le-moi)."
  fi
  sleep 2
}

set_default() {
  clear 2>/dev/null || true
  local sel; sel="$(accounts | gum choose --header "Compte par défaut ?" --cursor "❯ " --cursor.foreground "$ORANGE")" || return
  [ -n "$sel" ] && { printf '%s' "$sel" > "$ROOT/ACTIVE"; gum style --foreground "$OK" "✓ Défaut : « $sel »"; sleep 1; }
}

do_refresh() {
  clear 2>/dev/null || true
  gum style --foreground "$ORANGE" --bold --margin "1 0 1 2" "🔄  Rafraîchissement email + quota…"
  refresh_all_stats
  gum style --foreground "$OK" --margin "0 0 0 2" "✓ À jour."
  sleep 1
}

detail_stats() {
  clear 2>/dev/null || true
  local nb=0 conn=0 tot=0 proj=0 n
  while read -r n; do [ -n "$n" ] || continue; nb=$((nb+1)); { cc_has_login "$n" || [ -f "$ROOT/config/$n/oauth.token" ]; } && conn=$((conn+1)); tot=$((tot+$(count_sessions "$n"))); proj=$((proj+$(count_projects "$n"))); done <<< "$(accounts)"
  gum style --border double --border-foreground "$ORANGE" --padding "0 3" --margin "1 0 1 2" --foreground "$ORANGE" --bold "STATISTIQUES DÉTAILLÉES"
  {
    echo "## Système"
    echo "- **Version** : $(ver_str)  ·  **Plateforme** : $(os_label) ($PLAT)  ·  **Binaires** : $(plats_present)"
    echo "- **Espace libre** : $(free_space)  ·  **Taille install** : $(install_size)"
    echo
    echo "## Comptes  ($nb · $conn connectés · $tot sessions · $proj projets)"
    while read -r n; do
      [ -n "$n" ] || continue
      if [ -f "$ROOT/config/$n/.stats" ]; then
        echo "- **$n** — $(cc_stats_get "$n" email) ($(cc_stats_get "$n" plan)) · 5h $(cc_stats_get "$n" five)% · 7j $(cc_stats_get "$n" seven)% · $(count_sessions "$n") sessions"
      else
        echo "- **$n** — $(count_sessions "$n") sessions ($([ -f "$ROOT/config/$n/.credentials.json" ] && echo 'login, lance Rafraîchir' || echo 'token simple / non connecté'))"
      fi
    done <<< "$(accounts)"
  } | gum format | gum style --margin "0 0 1 2"
  printf '\n'; gum input --placeholder "Entrée pour revenir au menu" >/dev/null 2>&1 || true
}

do_update() { clear 2>/dev/null || true; gum style --foreground "$ORANGE" --bold --margin "1 0 1 2" "⬆  Mise à jour de Claude Code…"; cc_update; gum style --foreground "$OK" "✓ Terminé."; sleep 1; }
do_wipe()   { clear 2>/dev/null || true; if gum confirm "Tout déconnecter et effacer les sessions ?" --selected.background "$ORANGE"; then cc_wipe; gum style --foreground "$OK" "✓ Effacé. Révoque le token sur claude.ai si besoin."; else gum style --foreground "$DG" "Annulé."; fi; sleep 1; }
quit_wizard() {
  clear 2>/dev/null || true
  gum style --foreground "$ORANGE" --bold --margin "1 0 1 2" "À bientôt 👋"
  if [ "$CC_OS" = win32 ]; then exit 0; else exec "${SHELL:-/bin/zsh}" -l; fi
}

# ---------- préparation ----------
if [ ! -x "$GUMBIN" ] && [ ! -f "$GUMBIN" ]; then
  echo "Interface gum absente pour $PLAT — lancement direct du compte par défaut."
  cc_ensure_binary; p="$(cc_active_profile)"; cfg="$ROOT/config/$p"; cc_write_settings "$cfg"
  cc_has_login "$p" || cc_load_token "$p" || true
  export CLAUDE_CONFIG_DIR="$(cc_winpath "$cfg")"
  exec "$BIN" --dangerously-skip-permissions "$@"
fi
clear 2>/dev/null || true
gum spin --spinner dot --spinner.foreground "$ORANGE" --title "Préparation…" -- sleep 1
cc_ensure_binary

# ---------- boucle wizard ----------
while true; do
  render
  choice="$(gum choose --cursor "❯ " --cursor.foreground "$ORANGE" \
    "▶  Lancer le compte actif" \
    "↪  Lancer un autre compte" \
    "🔄  Rafraîchir email + quota" \
    "➕  Ajouter / reconnecter un compte" \
    "⭐  Changer le compte par défaut" \
    "📊  Statistiques détaillées" \
    "⬆  Mettre à jour Claude" \
    "🗑  Tout déconnecter" \
    "✕  Quitter")"; rc=$?
  if [ "$rc" -ne 0 ]; then if [ "$rc" -eq 130 ]; then continue; else break; fi; fi
  case "$choice" in
    "▶"*)  launch "$(cc_active_profile)" ;;
    "↪"*)  sel="$(choose_account)" && [ -n "$sel" ] && launch "$sel" ;;
    "🔄"*) do_refresh ;;
    "➕"*) add_account ;;
    "⭐"*) set_default ;;
    "📊"*) detail_stats ;;
    "⬆"*)  do_update ;;
    "🗑"*) do_wipe ;;
    "✕"*)  quit_wizard ;;
    *)     continue ;;
  esac
done
quit_wizard

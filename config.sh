#!/usr/bin/env bash
# Interactive setup for the API keys srt's optional, opt-in steps use:
# Google Custom Search (srt dork -search) and ProjectDiscovery's chaos +
# uncover (subfinder's chaos source, pipeline's options.uncover). Every one
# of these is off by default and skips cleanly without a key -- this script
# is only for turning them on, never required to use srt itself.
#
# Usage:
#   ./config.sh                      # guided wizard, prompts for each key
#   ./config.sh --status             # show what's currently configured (masked)
#   ./config.sh --set NAME=VALUE     # set one var non-interactively (repeatable)
#   ./config.sh --unset NAME         # remove one var (repeatable)
#   ./config.sh --unset-all          # remove everything this script manages
#
# Keys are written to ~/.config/srt/env (mode 600, one `export NAME="..."`
# line per key) and that file is sourced from your shell profile
# (~/.bashrc / ~/.zshrc / ~/.profile, whichever exist) so every new shell
# picks them up -- `source ~/.config/srt/env` (or restart your shell) to
# pick them up in the current one. Run with --set/--unset from a script
# without ever touching your shell profile by setting SRT_CONFIG_NO_HOOK=1.
#
# Never run this with sudo: these are your own personal API keys, meant for
# your own shell, not root's.
set -euo pipefail

# Refuse only the "sudo ./config.sh" case (a real user escalated to root):
# that would write the keys into root's $HOME, not theirs. Running as root
# directly (a container, a root-only box) has no other user to redirect to,
# so that's left alone -- $HOME is this identity's own, same as any other
# tool.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  echo "error: don't run config.sh with sudo -- these are your own API keys for your own shell. Run it as yourself: ./config.sh" >&2
  exit 1
fi

CONFIG_DIR="${SRT_CONFIG_DIR:-$HOME/.config/srt}"
ENV_FILE="${CONFIG_DIR}/env"

STATUS=0
UNSET_ALL=0
declare -a SET_ARGS=()
declare -a UNSET_ARGS=()

# --set/--unset accept their argument either as --set=NAME=VALUE or as the
# next argv word (--set NAME=VALUE), so this is a manual index loop rather
# than a plain `for arg in "$@"`.
args=("$@")
i=0
while [ "$i" -lt "$#" ]; do
  a="${args[$i]}"
  case "$a" in
    --status) STATUS=1 ;;
    --unset-all) UNSET_ALL=1 ;;
    --set=*) SET_ARGS+=("${a#--set=}") ;;
    --set)
      i=$((i + 1))
      SET_ARGS+=("${args[$i]:-}")
      ;;
    --unset=*) UNSET_ARGS+=("${a#--unset=}") ;;
    --unset)
      i=$((i + 1))
      UNSET_ARGS+=("${args[$i]:-}")
      ;;
    -h | --help)
      sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option: $a (see --help)" >&2
      exit 1
      ;;
  esac
  i=$((i + 1))
done

# --- known credentials -------------------------------------------------
# name|VAR[,VAR2]|description
CREDENTIALS=(
  "Google Custom Search (srt dork -search)|SRT_GOOGLE_API_KEY,SRT_GOOGLE_CSE_ID"
  "chaos (subfinder's chaos subdomain source)|SRT_CHAOS_API_KEY"
  "Shodan (uncover -e shodan, pipeline's options.uncover)|SHODAN_API_KEY"
  "Censys (uncover -e censys)|CENSYS_API_TOKEN,CENSYS_ORGANIZATION_ID"
  "FOFA (uncover -e fofa)|FOFA_EMAIL,FOFA_KEY"
)

mask() {
  local v="$1" n
  n=${#v}
  if [ "$n" -le 6 ]; then
    printf '%s' "******"
  else
    printf '%s' "${v:0:4}$(printf '%*s' $((n - 6)) '' | tr ' ' '*')${v: -2}"
  fi
}

ensure_env_file() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"
  [ -f "$ENV_FILE" ] || : > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

# currently-set value for NAME: the env file wins (it's what persists),
# falling back to whatever's already exported in this shell.
configured() {
  local name="$1" v
  if [ -f "$ENV_FILE" ]; then
    v="$(sed -n "s/^export ${name}=\"\(.*\)\"\$/\1/p" "$ENV_FILE" | tail -1)"
    if [ -n "$v" ]; then
      printf '%s' "$v"
      return
    fi
  fi
  printf '%s' "${!name:-}"
}

set_var() {
  local name="$1" value="$2"
  ensure_env_file
  local esc=${value//\\/\\\\}
  esc=${esc//\"/\\\"}
  local tmp
  tmp="$(mktemp "${CONFIG_DIR}/.env.XXXXXX")"
  grep -v "^export ${name}=" "$ENV_FILE" > "$tmp" 2>/dev/null || true
  printf 'export %s="%s"\n' "$name" "$esc" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

unset_var() {
  local name="$1"
  [ -f "$ENV_FILE" ] || return 0
  local tmp
  tmp="$(mktemp "${CONFIG_DIR}/.env.XXXXXX")"
  grep -v "^export ${name}=" "$ENV_FILE" > "$tmp" 2>/dev/null || true
  mv "$tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

hook_shell_profile() {
  [ "${SRT_CONFIG_NO_HOOK:-0}" = "1" ] && return 0
  local line="[ -f \"${ENV_FILE}\" ] && . \"${ENV_FILE}\"  # srt: API keys for dork/uncover, see config.sh"
  local hooked=0 profile
  for profile in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$profile" ] || continue
    grep -qF "$ENV_FILE" "$profile" 2>/dev/null && { hooked=1; continue; }
    printf '\n%s\n' "$line" >> "$profile"
    echo "Added to ${profile}: source ${ENV_FILE}" >&2
    hooked=1
  done
  if [ "$hooked" -eq 0 ]; then
    profile="$HOME/.profile"
    if ! grep -qF "$ENV_FILE" "$profile" 2>/dev/null; then
      printf '\n%s\n' "$line" >> "$profile"
      echo "Added to ${profile}: source ${ENV_FILE}" >&2
    fi
  fi
}

print_status() {
  ensure_env_file
  echo "Config file: ${ENV_FILE}"
  echo
  local entry title vars v name any
  for entry in "${CREDENTIALS[@]}"; do
    title="${entry%%|*}"
    vars="${entry#*|}"
    echo "${title}:"
    any=0
    IFS=, read -r -a names <<< "$vars"
    for name in "${names[@]}"; do
      v="$(configured "$name")"
      if [ -n "$v" ]; then
        echo "  ${name} = $(mask "$v")"
        any=1
      else
        echo "  ${name} = (not set)"
      fi
    done
    [ "$any" -eq 1 ] || echo "  -- not configured"
    echo
  done
}

# This script is meant to work piped from curl too (`curl ... | bash`),
# which consumes stdin for the script itself, so prompts read straight from
# the controlling terminal (/dev/tty) rather than stdin. No terminal at all
# (a fully non-interactive run) falls back to "no"/empty rather than an
# error -- e.g. CI invoking this by accident gets a no-op wizard, not a
# crash.
#
# [ -r /dev/tty ] alone isn't enough to detect this: the device node's
# permission bits can look readable even with no controlling terminal
# attached at all (this sandbox is exactly that case) -- only an actual
# open attempt reliably fails (ENXIO) the way a real `read ... </dev/tty`
# would, so that's what this checks instead.
have_tty() {
  { : < /dev/tty; } 2>/dev/null
}

confirm() {
  local prompt="$1" reply=""
  if have_tty; then
    read -r -p "${prompt} [y/N] " reply < /dev/tty > /dev/tty 2>&1 || reply=""
  fi
  case "$reply" in
    [yY] | [yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

prompt_value() {
  local label="$1" secret="${2:-1}" val=""
  if have_tty; then
    if [ "$secret" = "1" ]; then
      read -r -s -p "  ${label}: " val < /dev/tty > /dev/tty 2>&1 || val=""
      echo > /dev/tty
    else
      read -r -p "  ${label}: " val < /dev/tty > /dev/tty 2>&1 || val=""
    fi
  fi
  printf '%s' "$val"
}

# guided_credential name docs... -- prints the given doc lines, then offers
# to set each VAR in `vars` (comma list) interactively.
guided_credential() {
  local title="$1" vars="$2"
  shift 2
  echo "== ${title} =="
  local line
  for line in "$@"; do
    echo "  ${line}"
  done
  IFS=, read -r -a names <<< "$vars"
  local any_set=0 name v
  for name in "${names[@]}"; do
    v="$(configured "$name")"
    [ -n "$v" ] && { echo "  currently: ${name} = $(mask "$v")"; any_set=1; }
  done
  local verb="Configure"
  [ "$any_set" -eq 1 ] && verb="Update"
  if ! confirm "${verb} ${title} now?"; then
    echo
    return 0
  fi
  for name in "${names[@]}"; do
    v="$(prompt_value "$name")"
    if [ -n "$v" ]; then
      set_var "$name" "$v"
    else
      echo "  (left blank, not changed)" >&2
    fi
  done
  echo "Saved." >&2
  echo
}

run_wizard() {
  if ! have_tty; then
    echo "No terminal to prompt on (this needs to run interactively)." >&2
    echo "Use non-interactive mode instead: ./config.sh --set NAME=VALUE" >&2
    echo "See what's configurable with: ./config.sh --help" >&2
    exit 1
  fi

  echo "srt credential setup -- every one of these is optional and off by"
  echo "default; srt works fully without any of them. Press Ctrl+C anytime"
  echo "to stop; nothing is saved until you confirm each one."
  echo

  guided_credential \
    "Google Custom Search (srt dork -search)" \
    "SRT_GOOGLE_API_KEY,SRT_GOOGLE_CSE_ID" \
    "Lets 'srt dork -search' actually run dork queries via Google's Custom" \
    "Search JSON API, instead of just printing search URLs to paste by hand." \
    "Free tier: 100 queries/day (srt enforces that cap itself, see" \
    "gotools/docs/commands.md#dork). Setup (~2 minutes):" \
    "1. https://console.cloud.google.com/apis/library/customsearch.googleapis.com" \
    "   -- enable the Custom Search API (create/select a project if asked)" \
    "2. https://console.cloud.google.com/apis/credentials" \
    "   -- Create Credentials -> API key" \
    "3. https://programmablesearchengine.google.com/" \
    "   -- create a search engine, turn ON \"Search the entire web\"," \
    "      copy its Search engine ID (cx)"

  guided_credential \
    "chaos (ProjectDiscovery, subfinder's chaos subdomain source)" \
    "SRT_CHAOS_API_KEY" \
    "Adds chaos's subdomain dataset to the WEB stage's passive subdomain" \
    "discovery (subfinder already has this source built in -- it just" \
    "needs a key). Setup:" \
    "1. https://chaos.projectdiscovery.io/ -- sign up (free)" \
    "2. Copy your API key from the dashboard"

  guided_credential \
    "Shodan (uncover -e shodan -- pipeline's options.uncover scope-seeding)" \
    "SHODAN_API_KEY" \
    "Lets pipeline's options.uncover/-uncover seed HOST targets from a" \
    "Shodan search (e.g. org:\"Acme Corp\"); uncover's default engine." \
    "Setup:" \
    "1. https://account.shodan.io/register -- sign up (free tier exists)" \
    "2. Your API key is on https://account.shodan.io/"

  guided_credential \
    "Censys (uncover -e censys)" \
    "CENSYS_API_TOKEN,CENSYS_ORGANIZATION_ID" \
    "An alternative/additional uncover search engine. Setup:" \
    "1. https://censys.io/ -- sign up" \
    "2. API token and organization ID are on your Censys account/org page"

  guided_credential \
    "FOFA (uncover -e fofa)" \
    "FOFA_EMAIL,FOFA_KEY" \
    "Another alternative/additional uncover search engine. Setup:" \
    "1. https://fofa.info/ -- sign up" \
    "2. Your API key is on the personal center / account page"

  echo "That's every credential this wizard guides -- uncover also"
  echo "supports quake, hunter, zoomeye, netlas, criminalip, publicwww,"
  echo "hunterhow, binaryedge, onyphe, driftnet, greynoise, daydaymap,"
  echo "nerdydata, and odin by setting their own env var directly (see"
  echo "gotools/docs/ROADMAP.md, gap 11, for the full list) -- this script"
  echo "doesn't prompt for those, but ${ENV_FILE} is a plain shell file you"
  echo "can add \`export THAT_VAR=\"...\"\` lines to by hand."
  echo
  hook_shell_profile
  echo
  echo "Done. Run '. ${ENV_FILE}' (or open a new shell) to pick these up now."
  echo "Check anytime with: ./config.sh --status"
}

# --- dispatch ------------------------------------------------------------

if [ "$UNSET_ALL" -eq 1 ]; then
  ensure_env_file
  : > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Cleared ${ENV_FILE}." >&2
  exit 0
fi

if [ "${#UNSET_ARGS[@]}" -gt 0 ]; then
  ensure_env_file
  for name in "${UNSET_ARGS[@]}"; do
    [ -n "$name" ] || continue
    unset_var "$name"
    echo "Unset ${name}." >&2
  done
  exit 0
fi

if [ "${#SET_ARGS[@]}" -gt 0 ]; then
  ensure_env_file
  for kv in "${SET_ARGS[@]}"; do
    [ -n "$kv" ] || continue
    case "$kv" in
      *=*)
        name="${kv%%=*}"
        value="${kv#*=}"
        set_var "$name" "$value"
        echo "Set ${name}." >&2
        ;;
      *)
        echo "error: --set expects NAME=VALUE, got: ${kv}" >&2
        exit 1
        ;;
    esac
  done
  hook_shell_profile
  exit 0
fi

if [ "$STATUS" -eq 1 ]; then
  print_status
  exit 0
fi

run_wizard

#!/bin/bash

# ── Input ─────────────────────────────────────────────────────────────────────
input=$(cat)

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
jq_field() { echo "$input" | jq -r "$1" 2>/dev/null; }

format_number() {
  local num=$1
  if   (( num >= 1000000 )); then awk "BEGIN { printf \"%.1fm\", $num/1000000 }"
  elif (( num >= 1000    )); then awk "BEGIN { printf \"%.1fk\", $num/1000 }"
  else echo "$num"
  fi
}

normalize_remote_url() {
  local url="$1"
  [[ -z "$url" ]] && return
  if [[ "$url" == git@*:* ]]; then
    local host_path="${url#git@}"
    echo "https://${host_path%%:*}/${host_path#*:}" | sed 's/\.git$//'
  elif [[ "$url" == http://* || "$url" == https://* ]]; then
    echo "${url%.git}"
  else
    echo "$url"
  fi
}

to_hyperlink() {
  printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$1" "$2"
}

supports_osc8() {
  [[ "${TERM_PROGRAM:-}" == "vscode"    ]] && return 0
  [[ "${TERM_PROGRAM:-}" == "iTerm.app" ]] && return 0
  [[ "${TERM_PROGRAM:-}" == "WezTerm"   ]] && return 0
  [[ -n "${KITTY_WINDOW_ID:-}"          ]] && return 0
  [[ -n "${WT_SESSION:-}"               ]] && return 0
  [[ -n "${VTE_VERSION:-}"              ]] && return 0
  return 1
}

# ── Extract values ────────────────────────────────────────────────────────────
MODEL=$(jq_field '.model.display_name // "unknown-model"')
DIR=$(jq_field '.workspace.current_dir // .cwd // empty')
COST_USD=$(jq_field '.cost.total_cost_usd // 0')
CONTEXT_PCT=$(jq_field '.context_window.used_percentage // 0' | cut -d. -f1)
CONTEXT_PCT=${CONTEXT_PCT:-0}
(( CONTEXT_PCT < 0   )) && CONTEXT_PCT=0
(( CONTEXT_PCT > 100 )) && CONTEXT_PCT=100
INPUT_TOKENS=$(jq_field '.context_window.total_input_tokens // 0')
OUTPUT_TOKENS=$(jq_field '.context_window.total_output_tokens // 0')
LINES_ADDED=$(jq_field '.cost.total_lines_added // 0')
LINES_REMOVED=$(jq_field '.cost.total_lines_removed // 0')
WORKTREE_NAME=$(jq_field '.worktree.name // empty')

[[ -z "$DIR" ]] && DIR=$(pwd)

# ── Git context ───────────────────────────────────────────────────────────────
BRANCH=""
if git -C "$DIR" rev-parse --git-dir > /dev/null 2>&1; then
  BRANCH_NAME=$(git -C "$DIR" branch --show-current 2>/dev/null)
  [[ -z "$BRANCH_NAME" ]] && BRANCH_NAME=$(git -C "$DIR" rev-parse --short HEAD 2>/dev/null)

  ORIGIN_REMOTE=$(git -C "$DIR" remote get-url origin 2>/dev/null || true)
  REPO_URL=$(normalize_remote_url "$ORIGIN_REMOTE")

  # Detect worktree name from physical directory (not git registration name,
  # which may differ if the worktree directory was renamed after creation).
  if [[ -z "$WORKTREE_NAME" ]]; then
    GIT_DIR_PATH=$(git -C "$DIR" rev-parse --git-dir 2>/dev/null || true)
    [[ "$GIT_DIR_PATH" == *"/worktrees/"* ]] && WORKTREE_NAME=$(basename "$DIR")
  fi

  if [[ -n "$BRANCH_NAME" ]]; then
    # Strip common prefixes (user/<name>/, feature/, fix/, etc.) to shorten display
    SHORT_BRANCH="$BRANCH_NAME"
    SHORT_BRANCH="${SHORT_BRANCH#user/*/}"
    SHORT_BRANCH="${SHORT_BRANCH#users/*/}"
    [[ "$SHORT_BRANCH" == "$BRANCH_NAME" ]] && SHORT_BRANCH=$(echo "$BRANCH_NAME" | sed 's|^[^/]*/[^/]*/||')
    [[ -z "$SHORT_BRANCH" || "$SHORT_BRANCH" == "$BRANCH_NAME" ]] && SHORT_BRANCH="$BRANCH_NAME"
    # Plain text branch for line 2 — OSC8 hyperlinks add ~170 invisible bytes that inflate
    # Claude Code's width measurement and cause the whole line to be replaced with "..."
    BRANCH="🌿 ${SHORT_BRANCH}"
  fi
fi

# ── Context bar ───────────────────────────────────────────────────────────────
if   (( CONTEXT_PCT >= 80 )); then BAR_COLOR="$RED"
elif (( CONTEXT_PCT >= 65 )); then BAR_COLOR="$YELLOW"
else                               BAR_COLOR="$GREEN"
fi

FILLED=$((CONTEXT_PCT / 10))
printf -v FILL "%${FILLED}s"
printf -v PAD  "%$((10 - FILLED))s"
BAR="${FILL// /█}${PAD// /░}"

# ── Output ────────────────────────────────────────────────────────────────────
COST_FMT=$(printf '$%.2f' "$COST_USD")
IN_FMT=$(format_number "$INPUT_TOKENS")
OUT_FMT=$(format_number "$OUTPUT_TOKENS")

echo -e "🧠 [$MODEL] | ${BAR_COLOR}${BAR}${RESET} ${CONTEXT_PCT}% | 💵 ${COST_FMT} | ⬇️ ${IN_FMT} | ⬆️ ${OUT_FMT}"

DIR_BASENAME="${DIR##*/}"
SECOND_LINE="📁 ${DIR_BASENAME}"
[[ -n "$BRANCH"        ]] && SECOND_LINE+=" | $BRANCH"
[[ -n "$WORKTREE_NAME" ]] && SECOND_LINE+=" | 🪵 $WORKTREE_NAME"
SECOND_LINE+=" | \033[32m+${LINES_ADDED}\033[0m \033[31m-${LINES_REMOVED}\033[0m"

# Truncate to max visible width — strip ANSI codes to measure, then cut the raw string
MAX_VISIBLE=120
strip_ansi() { printf '%s' "$1" | sed $'s/\033\\[[0-9;]*m//g'; }
VISIBLE=$(strip_ansi "$SECOND_LINE")
if (( ${#VISIBLE} > MAX_VISIBLE )); then
  # Trim ANSI-stripped version then reattach the color suffix for +/- stats
  STATS_PLAIN=" | +${LINES_ADDED} -${LINES_REMOVED}"
  STATS_COLOR=" | \033[32m+${LINES_ADDED}\033[0m \033[31m-${LINES_REMOVED}\033[0m"
  BUDGET=$(( MAX_VISIBLE - ${#STATS_PLAIN} - 2 ))  # 2 for ".."
  SECOND_LINE="${VISIBLE:0:$BUDGET}..${STATS_COLOR}"
fi
echo -e "$SECOND_LINE"

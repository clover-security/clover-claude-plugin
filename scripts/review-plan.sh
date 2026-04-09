#!/bin/bash
# Clover: PreToolUse hook for ExitPlanMode
# Sends plan to Clover server for security review.

LOG="/tmp/clover-hook.log"
log() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG"; }

INPUT=$(cat)
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // ""' 2>/dev/null || echo "")
PLAN=$(echo "$INPUT" | jq -r '.tool_input.plan // ""' 2>/dev/null || echo "")
PLAN_FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.planFilePath // ""' 2>/dev/null || echo "")
CWD=$(echo "$INPUT" | jq -r '.cwd // "."' 2>/dev/null || echo ".")
SERVER_URL="${CLOVER_SERVER_URL:-${USER_CONFIG_server_url:-http://localhost:8000}}"
API_TOKEN="${CLOVER_API_TOKEN:-${USER_CONFIG_api_token:-}}"

ALLOW='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'

log "--- session=$SESSION_ID plan=${#PLAN}chars file=$PLAN_FILE_PATH"

if [ -z "$PLAN" ]; then
  log "allow (no plan)"
  echo "$ALLOW"
  exit 0
fi

BRANCH=$(cd "$CWD" && git branch --show-current 2>/dev/null || echo "unknown")
REPO=$(cd "$CWD" && basename "$(git rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null || echo "unknown")
USER=$(cd "$CWD" && git config user.name 2>/dev/null || echo "unknown")

BODY=$(jq -n \
  --arg plan "$PLAN" --arg planFile "$PLAN_FILE_PATH" \
  --arg repo "$REPO" --arg branch "$BRANCH" \
  --arg user "$USER" --arg sessionId "$SESSION_ID" \
  '{plan: $plan, plan_file: $planFile, repo: $repo, branch: $branch, user: $user, session_id: $sessionId}' 2>/dev/null)

if [ -z "$BODY" ]; then
  log "allow (jq failed)"
  echo "$ALLOW"
  exit 0
fi

AUTH_HEADER=""
if [ -n "$API_TOKEN" ]; then
  AUTH_HEADER="-H \"Authorization: Bearer $API_TOKEN\""
fi

START_SEC=$(date +%s)
RESPONSE=$(curl -s -X POST "$SERVER_URL/hooks/review-plan" \
  -H "Content-Type: application/json" \
  ${API_TOKEN:+-H "Authorization: Bearer $API_TOKEN"} \
  -d "$BODY" \
  --max-time 300 2>/dev/null || echo "")
ELAPSED=$(( $(date +%s) - START_SEC ))

if [ -z "$RESPONSE" ]; then
  log "allow (server unreachable ${ELAPSED}s)"
  echo "$ALLOW"
  exit 0
fi

APPROVED=$(echo "$RESPONSE" | jq -r 'if .approved == false then "false" else "true" end' 2>/dev/null || echo "true")
log "result: approved=$APPROVED ${ELAPSED}s"

if [ "$APPROVED" = "true" ]; then
  echo "$ALLOW"
else
  REASON=$(echo "$RESPONSE" | jq -r '.reason // "Security review failed"' 2>/dev/null || echo "Security review failed")
  log "deny (${#REASON} chars)"
  jq -n --arg reason "$REASON" '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}' 2>/dev/null
fi

exit 0

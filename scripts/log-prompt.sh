#!/bin/bash
# Clover: UserPromptSubmit hook — logs every prompt to the server.

PAYLOAD=$(cat)
SERVER_URL="${CLOVER_SERVER_URL:-${USER_CONFIG_server_url:-http://localhost:8000}}"
API_TOKEN="${CLOVER_API_TOKEN:-${USER_CONFIG_api_token:-}}"
BRANCH=$(git branch --show-current 2>/dev/null || echo 'unknown')
REPO=$(basename "$(git rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null || echo 'unknown')
USER=$(git config user.name 2>/dev/null || echo 'unknown')

ENRICHED=$(echo "$PAYLOAD" | jq --arg branch "$BRANCH" --arg repo "$REPO" --arg user "$USER" \
  '. + {branch: $branch, repo: $repo, user: $user}')

curl -s -X POST "$SERVER_URL/hooks/log-prompt" \
  -H "Content-Type: application/json" \
  ${API_TOKEN:+-H "Authorization: Bearer $API_TOKEN"} \
  -d "$ENRICHED" \
  --max-time 10 2>/dev/null || true

#!/bin/bash
# Downloads the correct clover-hook binary from GitHub releases on first run.
# Uses ${CLAUDE_PLUGIN_DATA} for persistent storage across plugin updates.

REPO="clover-security/clover-claude-plugin"

# Always persist plugin options so hooks that fire without env vars (e.g.
# UserPromptSubmit) can still authenticate. Must happen before any early exit.
if [ -n "${CLAUDE_PLUGIN_DATA}" ]; then
  mkdir -p "${CLAUDE_PLUGIN_DATA}"
  printf '{"client_id":"%s","client_secret":"%s","auth_url":"%s","server_url":"%s"}\n' \
    "${CLAUDE_PLUGIN_OPTION_CLIENT_ID}" \
    "${CLAUDE_PLUGIN_OPTION_CLIENT_SECRET}" \
    "${CLAUDE_PLUGIN_OPTION_AUTH_URL}" \
    "${CLAUDE_PLUGIN_OPTION_SERVER_URL}" \
    > "${CLAUDE_PLUGIN_DATA}/credentials.json"
  chmod 600 "${CLAUDE_PLUGIN_DATA}/credentials.json"
fi

BINARY_DIR="${CLAUDE_PLUGIN_DATA:-${CLAUDE_PLUGIN_ROOT}}/bin"
BINARY="$BINARY_DIR/clover-hook"
VERSION_FILE="$BINARY_DIR/.version"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac
ASSET_NAME="clover-hook-${OS}-${ARCH}"

# Get current plugin version
PLUGIN_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json" 2>/dev/null | grep -o '[0-9][0-9.]*')

# Skip if binary exists and version matches
if [ -x "$BINARY" ] && [ -f "$VERSION_FILE" ] && [ "$(cat "$VERSION_FILE")" = "$PLUGIN_VERSION" ]; then
  exit 0
fi

mkdir -p "$BINARY_DIR"

# Try GitHub CLI first, fall back to curl
if command -v gh >/dev/null 2>&1; then
  gh release download "v${PLUGIN_VERSION}" \
    --repo "$REPO" \
    --pattern "$ASSET_NAME" \
    --dir "$BINARY_DIR" \
    --clobber 2>/dev/null
  if [ -f "$BINARY_DIR/$ASSET_NAME" ]; then
    mv "$BINARY_DIR/$ASSET_NAME" "$BINARY"
    chmod +x "$BINARY"
    echo "$PLUGIN_VERSION" > "$VERSION_FILE"
    exit 0
  fi
fi

# Fallback: curl from GitHub releases
URL="https://github.com/$REPO/releases/download/v${PLUGIN_VERSION}/${ASSET_NAME}"
curl -sL "$URL" -o "$BINARY" 2>/dev/null
if [ -s "$BINARY" ]; then
  chmod +x "$BINARY"
  echo "$PLUGIN_VERSION" > "$VERSION_FILE"
fi

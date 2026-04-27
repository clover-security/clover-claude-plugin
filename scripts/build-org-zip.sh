#!/usr/bin/env bash
# Builds a self-contained organization-distribution zip:
#   - Plugin manifest (.claude-plugin/plugin.json + marketplace.json)
#   - Hook config (hooks/hooks.json)
#   - README.md
#   - All four platform binaries (darwin/linux × arm64/amd64) under bin/
#   - A setup script that copies the right binary at SessionStart instead
#     of fetching from GitHub Releases.
#
# Output: dist/clover-plugin-v<version>.zip
#
# Usage:
#   ./scripts/build-org-zip.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' .claude-plugin/plugin.json | grep -o '[0-9][0-9.]*')
echo "Building offline distribution for clover-plugin v${VERSION}"

STAGE="dist/clover-plugin"
rm -rf dist
mkdir -p "$STAGE/.claude-plugin" "$STAGE/hooks" "$STAGE/scripts" "$STAGE/bin"

# Copy the static plugin files.
cp .claude-plugin/plugin.json "$STAGE/.claude-plugin/"
cp .claude-plugin/marketplace.json "$STAGE/.claude-plugin/"
cp hooks/hooks.json "$STAGE/hooks/"
cp README.md "$STAGE/"

# Build all four platform variants. Same flags as the GitHub release workflow.
for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
    GOOS="${target%/*}"
    GOARCH="${target#*/}"
    OUT="$STAGE/bin/clover-hook-${GOOS}-${GOARCH}"
    echo "  building ${OUT}"
    GOOS="$GOOS" GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$OUT" ./cmd/clover-hook
done

# Setup script: at SessionStart, detect OS/arch and copy the matching bundled
# binary into ${CLAUDE_PLUGIN_DATA}/bin/clover-hook. No network calls.
cat > "$STAGE/scripts/setup.sh" <<'SETUP'
#!/usr/bin/env bash
set -e

BINARY_DIR="${CLAUDE_PLUGIN_DATA:-${CLAUDE_PLUGIN_ROOT}}/bin"
BINARY="$BINARY_DIR/clover-hook"
VERSION_FILE="$BINARY_DIR/.version"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac
ASSET_NAME="clover-hook-${OS}-${ARCH}"

PLUGIN_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json" 2>/dev/null | grep -o '[0-9][0-9.]*')

# Same-version short-circuit so we don't reinstall every session.
if [ -x "$BINARY" ] && [ -f "$VERSION_FILE" ] && [ "$(cat "$VERSION_FILE")" = "$PLUGIN_VERSION" ]; then
  exit 0
fi

mkdir -p "$BINARY_DIR"

SRC="${CLAUDE_PLUGIN_ROOT}/bin/${ASSET_NAME}"
if [ ! -f "$SRC" ]; then
  echo "clover-plugin: bundled binary not found for ${OS}/${ARCH} (expected ${SRC})" >&2
  exit 1
fi

cp "$SRC" "$BINARY"
chmod +x "$BINARY"
echo "$PLUGIN_VERSION" > "$VERSION_FILE"
SETUP
chmod +x "$STAGE/scripts/setup.sh"

# Zip it.
ZIP="dist/clover-plugin-v${VERSION}.zip"
( cd dist && zip -r "$(basename "$ZIP")" clover-plugin >/dev/null )

SIZE=$(du -h "$ZIP" | cut -f1)
echo
echo "Done: $ZIP ($SIZE)"
echo
echo "To install in your Claude Code organization:"
echo "  unzip $ZIP -d ~/clover-plugin && \\"
echo "  claude plugin install ~/clover-plugin/clover-plugin"
echo
echo "Or distribute the zip directly — Claude Code can install from a local path."

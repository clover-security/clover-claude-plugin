#!/usr/bin/env bash
# Wrapper invoked by every Claude Code hook event (UserPromptSubmit,
# PreToolUse:ExitPlanMode). Claude Code only injects CLAUDE_PLUGIN_OPTION_*
# env vars during SessionStart — for any other event, plugin options are
# unset and the binary cannot authenticate. setup.sh persists those options
# to env.sh once per SessionStart; this wrapper sources them back in.
. "${CLAUDE_PLUGIN_DATA}/env.sh" 2>/dev/null
exec "${CLAUDE_PLUGIN_DATA}/bin/clover-hook" "$@"

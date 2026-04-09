# Clover — Claude Code Security Plugin

Automatically reviews implementation plans for security requirements before code is written.

## How it works

When you exit plan mode in Claude Code, Clover intercepts the plan, sends it for security analysis, and injects any missing security requirements back into the plan before implementation begins.

## Install

```bash
/plugin install clover@your-marketplace
```

You'll be prompted for:
- **server_url** — your Clover server endpoint
- **api_token** — authentication token

## What happens

1. You create a plan in Claude Code
2. When you exit plan mode → Clover reviews the plan
3. If security requirements are missing → Claude updates the plan
4. You approve the final plan → implementation begins

## Configuration

Override via environment variables:
```bash
export CLOVER_SERVER_URL=https://clover.yourcompany.com
export CLOVER_API_TOKEN=your-token
```

## Logs

Debug logs at `/tmp/clover-hook.log`

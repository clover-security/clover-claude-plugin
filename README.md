# Clover — Claude Code Security Plugin

Automatically reviews implementation plans for security requirements before code is written.

## How it works

When you exit plan mode in Claude Code, Clover intercepts the plan, sends it for security analysis, and injects any missing security requirements back into the plan before implementation begins.

## Install

**1. Add the Clover marketplace:**

```bash
claude plugin marketplace add https://github.com/clover-security/clover-claude-plugin.git
```

**2. Install the plugin:**

```bash
claude plugin install clover
```

You'll be prompted for:
- **server_url** — your Clover API server URL (e.g. `https://app.cloversec.io`)
- **auth_url** — your Frontegg auth URL (e.g. `https://clover.frontegg.com`)
- **client_id** — API client ID (from Clover Settings > API Tokens)
- **client_secret** — API client secret

## What happens

1. You create a plan in Claude Code
2. When you exit plan mode → Clover reviews the plan
3. If security requirements are missing → Claude updates the plan
4. You approve the final plan → implementation begins

## Configuration

Override via environment variables:
```bash
export CLOVER_SERVER_URL=https://app.cloversec.io
export CLOVER_AUTH_URL=https://clover.frontegg.com
export CLOVER_CLIENT_ID=your-client-id
export CLOVER_CLIENT_SECRET=your-client-secret
```

## Logs

Debug logs at `/tmp/clover-hook.log`

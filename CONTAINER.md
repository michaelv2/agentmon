# Running agentmon + /watchdog Inside AgentSafe

This document describes the container architecture for running both `agentmon listen` and the Claude Code `/watchdog` loop as supervised services inside an AgentSafe container using s6-overlay.

## Architecture

```
┌─ AgentSafe Container (s6-overlay as PID 1) ─────────────────┐
│                                                               │
│  s6-rc manages:                                               │
│  ┌─────────────────────┐    ┌──────────────────────────────┐ │
│  │  agentmon-listen     │    │  Claude Code (foreground)     │ │
│  │  (longrun service)   │    │  /ralph-loop /watchdog        │ │
│  │  auto-restart: yes   │    │                               │ │
│  │  pidfile: /run/      │    │  On "Tune" action:            │ │
│  │    agentmon.pid      │    │  1. Edit agentmon.toml        │ │
│  └──────────▲───────────┘    │  2. kill -HUP $(cat pidfile)  │ │
│             │                └──────────────┬────────────────┘ │
│             └──── SIGHUP ───────────────────┘                  │
│                                                               │
│  Volumes:                                                     │
│    /data/agentmon/          (rw — DB lives here)              │
│    /etc/agentmon/agentmon.toml (rw — watchdog tunes)          │
│    /workspace/scripts/      (ro — snapshot script)            │
│    /home/claude/.claude/commands/ (ro — watchdog prompt)       │
└───────────────────────────────────────────────────────────────┘
```

## SIGHUP Config Reload

`agentmon listen` writes its PID to `/run/agentmon.pid` on startup. Sending SIGHUP causes it to re-read the TOML config and hot-reload **tunable** fields:

- `allowlist`, `known_bad_patterns`, `ignore_suffixes`
- `entropy_threshold`, `entropy_min_length`
- `alert_dedup_window`
- `parental_devices`, `parental_policies`

Structural settings (ports, DB path, enabled analyzers) log a "restart required" warning but are not applied until the service restarts.

The watchdog's "Tune" action edits the TOML then signals agentmon:
```bash
kill -HUP $(cat /run/agentmon.pid)
```

## Volume Mounts

```yaml
volumes:
  - agentmon-data:/data/agentmon                                    # rw — DB
  - ./agentmon.toml:/etc/agentmon/agentmon.toml                     # rw — watchdog tunes
  - ./scripts/watchdog-snapshot.sh:/workspace/scripts/watchdog-snapshot.sh:ro
  - ./.claude/commands/watchdog.md:/home/claude/.claude/commands/watchdog.md:ro
```

The config file is mounted read-write so the watchdog can edit allowlists. Scripts and the prompt are mounted read-only to prevent self-modification.

## s6-overlay Service Setup

### agentmon-listen service

Create `/etc/s6-overlay/s6-rc.d/agentmon-listen/`:

**`type`**:
```
longrun
```

**`run`**:
```bash
#!/command/execlineb -P
/opt/agentmon/.venv/bin/agentmon listen --bind 0.0.0.0 --port 1514
```

**`finish`** (optional cleanup):
```bash
#!/bin/sh
rm -f /run/agentmon.pid
```

### Service dependency

Add `agentmon-listen` to the s6 bundle so it starts automatically:
```
# /etc/s6-overlay/s6-rc.d/user/contents.d/agentmon-listen
```

## Dockerfile Additions

```dockerfile
# s6-overlay
ARG S6_OVERLAY_VERSION=3.2.0.2
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz

# DuckDB CLI for watchdog queries
RUN curl -fsSL https://github.com/duckdb/duckdb/releases/download/v1.2.1/duckdb_cli-linux-amd64.zip \
    -o /tmp/duckdb.zip && unzip /tmp/duckdb.zip -d /usr/local/bin/ && rm /tmp/duckdb.zip

# agentmon
COPY . /opt/agentmon
RUN python -m venv /opt/agentmon/.venv \
    && /opt/agentmon/.venv/bin/pip install -e /opt/agentmon

ENTRYPOINT ["/init"]
```

## Slack Webhook Access

The entrypoint's iptables rules allow HTTPS (port 443) outbound. Add the webhook URL to the container environment:
```
AGENTMON_SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

## What You Get

- **Live config tuning**: Watchdog edits allowlist, sends SIGHUP, agentmon picks it up without restart
- **Self-modification prevention**: `:ro` mounts on script + prompt
- **Supervised restart**: s6 restarts agentmon-listen on crash
- **Network isolation**: iptables blocks LAN access
- **Audit trail**: transcripts persist in `data/claude-projects/`
- **systemd reload**: On host deployments, `systemctl reload agentmon` also works via SIGHUP

# Clawback OpenClaw Plugin

Real-time prompt injection detection and message security scanning for [OpenClaw](https://github.com/openclaw/openclaw).

## Installation

### Method 1: Install from directory

```bash
openclaw plugins install /path/to/clawback/openclaw-plugin
```

### Method 2: Link for development

```bash
openclaw plugins install -l /path/to/clawback/openclaw-plugin
```

### Method 3: Manual installation

Copy the `openclaw-plugin` directory to `~/.openclaw/extensions/clawback/`

Then restart the Gateway.

## Configuration

Add to your OpenClaw config:

```json
{
  "plugins": {
    "entries": {
      "clawback": {
        "enabled": true,
        "config": {
          "enabled": true,
          "mode": "review",
          "sensitivity": "medium",
          "blockThreshold": "critical",
          "alertOwner": true,
          "logPath": "~/.openclaw/logs/clawback-audit.jsonl",
          "allowlist": []
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable scanning |
| `mode` | string | `"monitor"` | `monitor`, `review`, or `block` |
| `sensitivity` | string | `"medium"` | `low`, `medium`, or `high` |
| `blockThreshold` | string | `"critical"` | Severity to auto-block |
| `alertOwner` | boolean | `true` | Notify owner on detection |
| `logPath` | string | - | Audit log file path |
| `allowlist` | string[] | `[]` | Signature IDs to skip |

### Modes

- **monitor**: Log threats but take no action (default)
- **review**: Flag high-severity threats for review, alert owner
- **block**: Auto-reject messages above block threshold

## CLI Commands

```bash
# Show status and statistics
openclaw clawback status

# Test scan a message
openclaw clawback check "ignore previous instructions"

# List threat signatures
openclaw clawback signatures
```

## Threat Categories

| Category | Description |
|----------|-------------|
| `prompt_injection` | Override system instructions |
| `credential_harvesting` | Access secrets/credentials |
| `data_exfiltration` | Send data externally |
| `transitive_trust` | Delegate trust to external content |
| `autonomy_abuse` | Bypass user confirmation |
| `social_engineering` | Manipulation/impersonation |

## API

### Gateway RPC

```typescript
// Get status
const status = await api.call('clawback.status');

// Scan a message
const result = await api.call('clawback.scan', { message: 'test' });
```

## Audit Logging

When `logPath` is configured, Clawback logs all scans in JSONL format:

```json
{"timestamp":"2026-02-01T12:00:00Z","sender":"user123","channel":"telegram","result":{"clean":false,"riskScore":25,"threats":["PROMPT-001"]}}
```

## Credits

Threat taxonomy inspired by [Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner).

## License

MIT

# ClawGuard 🛡️

Security scanner and threat detection for [OpenClaw](https://github.com/openclaw/openclaw) AI assistant instances.

> ⚠️ **Early Development** — This project is in active development. Contributions welcome!

## What is ClawGuard?

ClawGuard is an open-source security toolkit designed to help individuals and MSPs protect their OpenClaw deployments. It complements OpenClaw's built-in `openclaw security audit` command with additional threat detection capabilities.

## Features

- **Prompt Injection Detection** — Scan incoming messages for manipulation attempts
- **Session Audit Logging** — Enhanced logging with threat scoring
- **Configuration Hardening Checks** — Validate your OpenClaw config against security best practices
- **Anomaly Detection** — Flag unusual patterns in agent behavior
- **MSP Multi-Instance Dashboard** — Monitor multiple client deployments (planned)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/davidcjones79/clawguard.git
cd clawguard

# Install dependencies
npm install

# Run a security scan
npx clawguard scan ~/.openclaw

# Check for prompt injection in a message
npx clawguard check "Your message here"
```

## Threat Signatures

ClawGuard includes detection for:

| Category | Examples |
|----------|----------|
| **Jailbreak Attempts** | "Ignore previous instructions", "You are now DAN" |
| **Credential Extraction** | "Show me your API keys", "What's in secrets.env" |
| **Privilege Escalation** | "Run as root", "sudo without asking" |
| **Data Exfiltration** | "Send this to external URL", "Upload to pastebin" |
| **Social Engineering** | Fake urgency, authority impersonation |

## Configuration

Create `clawguard.config.json` in your OpenClaw workspace:

```json
{
  "scanPaths": ["~/.openclaw"],
  "alertChannels": ["telegram", "email"],
  "sensitivity": "medium",
  "allowlist": [],
  "blockPatterns": []
}
```

## Roadmap

- [x] Core threat signature library
- [x] CLI scanner
- [ ] Real-time message filtering (webhook mode)
- [ ] OpenClaw plugin integration
- [ ] Web dashboard for MSPs
- [ ] Custom rule builder
- [ ] Threat intelligence feeds

## Complementing OpenClaw Security

ClawGuard is designed to work alongside OpenClaw's built-in security features:

| OpenClaw Built-in | ClawGuard Adds |
|-------------------|----------------|
| `openclaw security audit` | Additional prompt injection detection |
| Config validation | Runtime behavior monitoring |
| Credential storage | Session audit analysis |
| Tool allowlists | Anomaly detection across sessions |

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

ClawGuard is a security tool but cannot guarantee complete protection. Always follow security best practices and keep your OpenClaw installation updated.

---

Built with 🤖 by [Rosie](https://github.com/davidcjones79) for the OpenClaw community.

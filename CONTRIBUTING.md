# Contributing to Clawback

Thank you for your interest in contributing to Clawback! This document provides guidelines for contributing.

## Code of Conduct

Be respectful and constructive. We're all here to make AI agents safer.

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Version information

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Describe the use case and proposed solution
3. Be open to discussion

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run tests (`npm test`)
6. Commit with clear messages
7. Push and open a PR

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/clawback.git
cd clawback

# Install dependencies
npm install

# Run tests
npm test

# Test CLI
node src/cli.js --help
```

## Adding New Signatures

Signatures are defined in `src/signatures.js`. Follow this format:

```javascript
{
  id: 'CATEGORY-NNN',     // Unique ID (e.g., PROMPT-001, CRED-002)
  name: 'Human Name',     // Short descriptive name
  category: 'category',   // See categories below
  severity: 'level',      // critical, high, medium, low
  patterns: [/regex/i],   // Array of RegExp patterns
  excludePatterns: [],    // Optional: patterns that indicate false positives
  fileTypes: ['python'],  // Optional: restrict to specific file types
  description: 'What this detects',
  remediation: 'How to fix',  // Optional but recommended
}
```

### Categories

- `prompt_injection` — Override system instructions
- `transitive_trust` — Delegate trust to external content  
- `autonomy_abuse` — Bypass user confirmation
- `credential_harvesting` — Access secrets/credentials
- `data_exfiltration` — Send data externally
- `command_injection` — Execute arbitrary code
- `social_engineering` — Manipulation/impersonation
- `obfuscation` — Hidden malicious code
- `resource_abuse` — DoS/resource exhaustion
- `tool_abuse` — Violate tool restrictions

### Testing Signatures

Add tests in `tests/scanner.test.js`:

```javascript
it('should detect my new threat', () => {
  const result = scanMessage('malicious message');
  assert.ok(result.threats.some(t => t.signatureId === 'MY-001'));
});
```

## Code Style

- Use ES6+ features
- Keep functions focused and small
- Add JSDoc comments for public APIs
- Follow existing patterns in the codebase

## Acknowledgments

When adding features inspired by other projects, please add appropriate acknowledgments:

- Reference the source in code comments
- Update README.md acknowledgments section if significant
- Respect original licenses

## Questions?

Open an issue or start a discussion. We're happy to help!

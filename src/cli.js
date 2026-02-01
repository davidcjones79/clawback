#!/usr/bin/env node
/**
 * Clawback CLI
 * Security scanner for OpenClaw instances
 */

const fs = require('fs');
const path = require('path');
const { scanMessage, auditConfig, signatures } = require('./scanner');

const VERSION = '0.1.0';

function printUsage() {
  console.log(`
Clawback v${VERSION} - Security scanner for OpenClaw

USAGE:
  clawback <command> [options]

COMMANDS:
  check <message>      Scan a message for prompt injection
  scan <path>          Scan an OpenClaw installation directory
  audit <config>       Audit an OpenClaw config file
  signatures           List all threat signatures
  version              Show version

OPTIONS:
  --sensitivity <low|medium|high>   Detection sensitivity (default: medium)
  --json                            Output as JSON
  --verbose                         Show detailed output

EXAMPLES:
  clawback check "ignore previous instructions"
  clawback scan ~/.openclaw
  clawback audit ~/.openclaw/config.yaml
  clawback signatures --json
`);
}

function formatThreat(threat) {
  const severityColors = {
    critical: '\x1b[31m', // red
    high: '\x1b[33m',     // yellow
    medium: '\x1b[36m',   // cyan
    low: '\x1b[37m',      // white
  };
  const reset = '\x1b[0m';
  const color = severityColors[threat.severity] || reset;
  
  return `  ${color}[${threat.severity.toUpperCase()}]${reset} ${threat.name} (${threat.signatureId})
    Match: "${threat.match}"
    ${threat.description}`;
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === 'help' || args[0] === '--help') {
    printUsage();
    process.exit(0);
  }
  
  const command = args[0];
  const flags = {
    json: args.includes('--json'),
    verbose: args.includes('--verbose'),
    sensitivity: 'medium',
  };
  
  const sensitivityIdx = args.indexOf('--sensitivity');
  if (sensitivityIdx !== -1 && args[sensitivityIdx + 1]) {
    flags.sensitivity = args[sensitivityIdx + 1];
  }
  
  switch (command) {
    case 'version':
    case '--version':
    case '-v':
      console.log(`Clawback v${VERSION}`);
      break;
      
    case 'check': {
      const message = args.slice(1).filter(a => !a.startsWith('--')).join(' ');
      if (!message) {
        console.error('Error: No message provided');
        console.error('Usage: clawback check "your message here"');
        process.exit(1);
      }
      
      const result = scanMessage(message, { sensitivity: flags.sensitivity });
      
      if (flags.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.clean) {
          console.log('✅ No threats detected');
          console.log(`Risk Score: ${result.riskScore}/100`);
        } else {
          console.log(`⚠️  ${result.threatCount} threat(s) detected!`);
          console.log(`Risk Score: ${result.riskScore}/100\n`);
          for (const threat of result.threats) {
            console.log(formatThreat(threat));
            console.log();
          }
        }
      }
      
      process.exit(result.clean ? 0 : 1);
      break;
    }
    
    case 'scan': {
      const scanPath = args[1] || path.join(process.env.HOME, '.openclaw');
      
      if (!fs.existsSync(scanPath)) {
        console.error(`Error: Path not found: ${scanPath}`);
        process.exit(1);
      }
      
      console.log(`Scanning ${scanPath}...`);
      
      // Look for config files
      const configFiles = ['config.yaml', 'config.yml', 'config.json'];
      let configFound = false;
      
      for (const configFile of configFiles) {
        const configPath = path.join(scanPath, configFile);
        if (fs.existsSync(configPath)) {
          console.log(`Found config: ${configPath}`);
          configFound = true;
          // TODO: Parse and audit config
        }
      }
      
      if (!configFound) {
        console.log('No config file found in directory');
      }
      
      // Check for sensitive files
      const sensitivePatterns = ['.env', 'secrets', 'credentials'];
      const files = fs.readdirSync(scanPath, { recursive: true });
      
      for (const file of files) {
        const filename = path.basename(file.toString()).toLowerCase();
        if (sensitivePatterns.some(p => filename.includes(p))) {
          console.log(`⚠️  Sensitive file found: ${file}`);
        }
      }
      
      console.log('\n✅ Scan complete');
      break;
    }
    
    case 'audit': {
      const configPath = args[1];
      if (!configPath) {
        console.error('Error: No config file specified');
        console.error('Usage: clawback audit <config-file>');
        process.exit(1);
      }
      
      if (!fs.existsSync(configPath)) {
        console.error(`Error: File not found: ${configPath}`);
        process.exit(1);
      }
      
      try {
        const content = fs.readFileSync(configPath, 'utf8');
        let config;
        
        if (configPath.endsWith('.json')) {
          config = JSON.parse(content);
        } else {
          // Basic YAML parsing for simple configs
          // TODO: Use proper YAML parser
          console.error('YAML parsing not yet implemented. Use JSON config.');
          process.exit(1);
        }
        
        const result = auditConfig(config);
        
        if (flags.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          if (result.secure) {
            console.log('✅ No security issues found');
          } else {
            console.log(`⚠️  ${result.issueCount} issue(s) found:\n`);
            for (const issue of result.issues) {
              console.log(`[${issue.severity.toUpperCase()}] ${issue.message}`);
              console.log(`  Path: ${issue.path}`);
              console.log();
            }
          }
        }
        
        process.exit(result.secure ? 0 : 1);
      } catch (err) {
        console.error(`Error reading config: ${err.message}`);
        process.exit(1);
      }
      break;
    }
    
    case 'signatures': {
      if (flags.json) {
        console.log(JSON.stringify(signatures, null, 2));
      } else {
        console.log(`Clawback Threat Signatures (${signatures.length} total)\n`);
        
        const byCategory = {};
        for (const sig of signatures) {
          if (!byCategory[sig.category]) byCategory[sig.category] = [];
          byCategory[sig.category].push(sig);
        }
        
        for (const [category, sigs] of Object.entries(byCategory)) {
          console.log(`\n${category.toUpperCase()}`);
          console.log('─'.repeat(40));
          for (const sig of sigs) {
            console.log(`  ${sig.id}: ${sig.name} [${sig.severity}]`);
            if (flags.verbose) {
              console.log(`    ${sig.description}`);
            }
          }
        }
      }
      break;
    }
    
    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

main();

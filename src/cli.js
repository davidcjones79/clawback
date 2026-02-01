#!/usr/bin/env node
/**
 * Clawback CLI
 * Security scanner for OpenClaw instances and Agent Skills
 * 
 * Inspired by Cisco AI Defense Skill Scanner
 * https://github.com/cisco-ai-defense/skill-scanner
 */

const fs = require('fs');
const path = require('path');
const { 
  scanMessage, 
  auditConfig, 
  scanOpenClawDirectory,
  auditSessionLogs,
  scanSkillDirectory,
  signatures 
} = require('./scanner');

const VERSION = '0.2.0';

function printUsage() {
  console.log(`
Clawback v${VERSION} - Security scanner for OpenClaw
https://github.com/davidcjones79/clawback

USAGE:
  clawback <command> [options]

COMMANDS:
  check <message>      Scan a message for prompt injection
  scan <path>          Scan an OpenClaw installation directory
  skill <path>         Scan an Agent Skill directory or SKILL.md
  audit <config>       Audit an OpenClaw config file
  logs <path>          Audit session log files for suspicious patterns
  signatures           List all threat signatures
  version              Show version

OPTIONS:
  --sensitivity <low|medium|high>   Detection sensitivity (default: medium)
  --json                            Output as JSON
  --verbose                         Show detailed output
  --sarif                           Output as SARIF (for CI/CD integration)

EXAMPLES:
  # Check a message for prompt injection
  clawback check "ignore previous instructions"
  
  # Scan OpenClaw installation
  clawback scan ~/.openclaw
  
  # Scan an Agent Skill
  clawback skill ./my-skill/
  
  # Audit config file
  clawback audit ~/.openclaw/config.json
  
  # Scan session logs
  clawback logs ~/.openclaw/agents/main/sessions/
  
  # List signatures with details
  clawback signatures --verbose

THREAT CATEGORIES:
  - prompt_injection    Override system instructions
  - transitive_trust    Delegate trust to external content
  - autonomy_abuse      Bypass user confirmation
  - credential_harvest  Access secrets/credentials
  - data_exfiltration   Send data externally
  - command_injection   Execute arbitrary code
  - social_engineering  Manipulation/impersonation
  - obfuscation         Hidden malicious code
  - resource_abuse      DoS/resource exhaustion

Threat taxonomy aligned with Cisco AI Defense Framework (AITech).
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
  
  let output = `  ${color}[${threat.severity.toUpperCase()}]${reset} ${threat.name} (${threat.signatureId})`;
  if (threat.file) {
    output += `\n    File: ${threat.file}${threat.line ? `:${threat.line}` : ''}`;
  }
  output += `\n    Match: "${threat.match}"`;
  output += `\n    ${threat.description}`;
  if (threat.remediation) {
    output += `\n    Fix: ${threat.remediation}`;
  }
  return output;
}

function formatConfigIssue(issue) {
  const severityColors = {
    critical: '\x1b[31m',
    high: '\x1b[33m',
    medium: '\x1b[36m',
    low: '\x1b[37m',
  };
  const reset = '\x1b[0m';
  const color = severityColors[issue.severity] || reset;
  
  let output = `  ${color}[${issue.severity.toUpperCase()}]${reset} ${issue.message}`;
  output += `\n    Path: ${issue.path}`;
  if (issue.remediation) {
    output += `\n    Fix: ${issue.remediation}`;
  }
  return output;
}

function toSARIF(results, ruleset = 'clawback') {
  // Convert results to SARIF format for GitHub Code Scanning
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Clawback',
          version: VERSION,
          informationUri: 'https://github.com/davidcjones79/clawback',
          rules: signatures.map(sig => ({
            id: sig.id,
            name: sig.name,
            shortDescription: { text: sig.description },
            defaultConfiguration: {
              level: sig.severity === 'critical' ? 'error' : 
                     sig.severity === 'high' ? 'warning' : 'note',
            },
          })),
        },
      },
      results: (results.threats || []).map(threat => ({
        ruleId: threat.signatureId,
        level: threat.severity === 'critical' ? 'error' :
               threat.severity === 'high' ? 'warning' : 'note',
        message: { text: `${threat.name}: ${threat.match}` },
        locations: threat.file ? [{
          physicalLocation: {
            artifactLocation: { uri: threat.file },
            region: threat.line ? { startLine: threat.line } : undefined,
          },
        }] : [],
      })),
    }],
  };
  
  return JSON.stringify(sarif, null, 2);
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
    sarif: args.includes('--sarif'),
    sensitivity: 'medium',
  };
  
  const sensitivityIdx = args.indexOf('--sensitivity');
  if (sensitivityIdx !== -1 && args[sensitivityIdx + 1]) {
    flags.sensitivity = args[sensitivityIdx + 1];
  }
  
  // Build set of args to exclude (flags and their values)
  const excludeArgs = new Set(['--json', '--verbose', '--sarif', '--sensitivity']);
  if (sensitivityIdx !== -1) {
    excludeArgs.add(args[sensitivityIdx + 1]); // Also exclude sensitivity value
  }
  
  switch (command) {
    case 'version':
    case '--version':
    case '-v':
      console.log(`Clawback v${VERSION}`);
      console.log('Security scanner for OpenClaw instances');
      console.log('Threat taxonomy inspired by Cisco AI Defense');
      break;
      
    case 'check': {
      const message = args.slice(1).filter(a => !a.startsWith('--') && !excludeArgs.has(a)).join(' ');
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
      
      console.log(`🔍 Scanning ${scanPath}...\n`);
      
      try {
        const result = scanOpenClawDirectory(scanPath);
        
        if (flags.json) {
          console.log(JSON.stringify(result, null, 2));
        } else if (flags.sarif) {
          // Flatten threats for SARIF
          const allThreats = [];
          if (result.configAudit?.issues) {
            allThreats.push(...result.configAudit.issues.map(i => ({
              ...i, signatureId: i.id, name: 'Config Issue',
            })));
          }
          for (const skill of result.skillScans) {
            allThreats.push(...(skill.threats || []));
          }
          console.log(toSARIF({ threats: allThreats }));
        } else {
          // Config audit results
          if (result.configAudit) {
            if (result.configAudit.secure) {
              console.log('📋 Config: ✅ No issues found\n');
            } else {
              console.log(`📋 Config: ⚠️  ${result.configAudit.issueCount} issue(s)\n`);
              for (const issue of result.configAudit.issues) {
                console.log(formatConfigIssue(issue));
                console.log();
              }
            }
          }
          
          // Skill scan results
          if (result.skillScans.length > 0) {
            console.log(`🧩 Skills scanned: ${result.skillScans.length}\n`);
            for (const skill of result.skillScans) {
              if (skill.clean) {
                console.log(`  ✅ ${skill.skill}: Clean`);
              } else {
                console.log(`  ⚠️  ${skill.skill}: ${skill.summary.totalThreats} threat(s)`);
                if (flags.verbose) {
                  for (const threat of skill.threats) {
                    console.log(formatThreat(threat));
                  }
                }
              }
            }
            console.log();
          }
          
          // Sensitive files
          if (result.sensitiveFiles.length > 0) {
            console.log(`🔐 Sensitive files found: ${result.sensitiveFiles.length}`);
            for (const file of result.sensitiveFiles) {
              console.log(`  - ${file.path}`);
            }
            console.log();
          }
          
          // Summary
          console.log('─'.repeat(40));
          console.log(`Risk Score: ${result.riskScore}/100`);
          console.log(`Total Issues: ${result.summary.totalThreats}`);
          console.log(`Critical: ${result.summary.criticalCount}`);
          
          if (result.clean) {
            console.log('\n✅ Scan complete - no issues found');
          } else {
            console.log('\n⚠️  Scan complete - issues found');
          }
        }
        
        process.exit(result.clean ? 0 : 1);
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }
    
    case 'skill': {
      const skillPath = args[1];
      if (!skillPath) {
        console.error('Error: No skill path provided');
        console.error('Usage: clawback skill ./path/to/skill/');
        process.exit(1);
      }
      
      if (!fs.existsSync(skillPath)) {
        console.error(`Error: Path not found: ${skillPath}`);
        process.exit(1);
      }
      
      console.log(`🔍 Scanning skill: ${skillPath}\n`);
      
      try {
        const result = scanSkillDirectory(skillPath);
        
        if (flags.json) {
          console.log(JSON.stringify(result, null, 2));
        } else if (flags.sarif) {
          console.log(toSARIF(result));
        } else {
          // Frontmatter info
          if (result.frontmatter?.name) {
            console.log(`📦 Skill: ${result.frontmatter.name}`);
            if (result.frontmatter.description) {
              console.log(`   ${result.frontmatter.description}`);
            }
            console.log();
          }
          
          // Files scanned
          console.log(`📄 Files scanned: ${result.summary.totalFiles}`);
          
          // Threats
          if (result.clean) {
            console.log('\n✅ No threats detected');
          } else {
            console.log(`\n⚠️  ${result.summary.totalThreats} threat(s) detected!\n`);
            
            // Group by severity
            const bySeverity = { critical: [], high: [], medium: [], low: [] };
            for (const threat of result.threats) {
              bySeverity[threat.severity].push(threat);
            }
            
            for (const severity of ['critical', 'high', 'medium', 'low']) {
              if (bySeverity[severity].length > 0) {
                for (const threat of bySeverity[severity]) {
                  console.log(formatThreat(threat));
                  console.log();
                }
              }
            }
          }
          
          console.log('─'.repeat(40));
          console.log(`Risk Score: ${result.riskScore}/100`);
        }
        
        process.exit(result.clean ? 0 : 1);
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
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
          console.error('YAML parsing not yet implemented. Use JSON config or install js-yaml.');
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
              console.log(formatConfigIssue(issue));
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
    
    case 'logs': {
      const logPath = args[1];
      if (!logPath) {
        console.error('Error: No log path specified');
        console.error('Usage: clawback logs <path-to-session-logs>');
        process.exit(1);
      }
      
      if (!fs.existsSync(logPath)) {
        console.error(`Error: Path not found: ${logPath}`);
        process.exit(1);
      }
      
      console.log(`🔍 Auditing session logs: ${logPath}\n`);
      
      auditSessionLogs(logPath).then(result => {
        if (flags.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`📊 Messages scanned: ${result.stats.totalMessages}`);
          console.log(`🚨 Flagged messages: ${result.stats.flaggedMessages}`);
          
          if (result.clean) {
            console.log('\n✅ No suspicious patterns found');
          } else {
            console.log('\n⚠️  Suspicious messages found:\n');
            for (const msg of result.suspiciousMessages.slice(0, 10)) {
              console.log(`  ${msg.file} (${msg.role || 'unknown'}):`);
              console.log(`    "${msg.preview}"`);
              for (const threat of msg.threats) {
                console.log(`    → ${threat.name} [${threat.severity}]`);
              }
              console.log();
            }
            if (result.suspiciousMessages.length > 10) {
              console.log(`  ... and ${result.suspiciousMessages.length - 10} more`);
            }
          }
          
          console.log('─'.repeat(40));
          console.log(`Risk Score: ${result.riskScore}/100`);
        }
        
        process.exit(result.clean ? 0 : 1);
      }).catch(err => {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      });
      break;
    }
    
    case 'signatures': {
      if (flags.json) {
        console.log(JSON.stringify(signatures, null, 2));
      } else {
        console.log(`Clawback Threat Signatures (${signatures.length} total)\n`);
        console.log('Threat taxonomy aligned with Cisco AI Defense Framework\n');
        
        const byCategory = {};
        for (const sig of signatures) {
          if (!byCategory[sig.category]) byCategory[sig.category] = [];
          byCategory[sig.category].push(sig);
        }
        
        for (const [category, sigs] of Object.entries(byCategory)) {
          console.log(`\n${category.toUpperCase().replace(/_/g, ' ')}`);
          console.log('─'.repeat(50));
          for (const sig of sigs) {
            console.log(`  ${sig.id}: ${sig.name} [${sig.severity}]`);
            if (flags.verbose) {
              console.log(`    ${sig.description}`);
              if (sig.remediation) {
                console.log(`    Fix: ${sig.remediation}`);
              }
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

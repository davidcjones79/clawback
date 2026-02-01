/**
 * Clawback OpenClaw Plugin
 * 
 * Real-time prompt injection detection and message security scanning.
 * Scans incoming messages before they reach the AI agent.
 * 
 * Threat taxonomy inspired by Cisco AI Defense Skill Scanner.
 * https://github.com/cisco-ai-defense/skill-scanner
 */

import type { PluginApi, PluginConfig } from 'openclaw';
import * as fs from 'fs';
import * as path from 'path';

// Inline the scanner to avoid external dependencies
// In production, you'd import from the clawback package

interface ClawbackConfig {
  enabled?: boolean;
  mode?: 'monitor' | 'review' | 'block';
  sensitivity?: 'low' | 'medium' | 'high';
  blockThreshold?: 'low' | 'medium' | 'high' | 'critical';
  alertOwner?: boolean;
  logPath?: string;
  allowlist?: string[];
}

interface Threat {
  signatureId: string;
  name: string;
  category: string;
  severity: string;
  match: string;
  description: string;
}

interface ScanResult {
  clean: boolean;
  threatCount: number;
  threats: Threat[];
  riskScore: number;
  scannedAt: string;
}

// Core threat signatures (subset for plugin - full set in main package)
const SIGNATURES = [
  // Prompt Injection
  {
    id: 'PROMPT-001',
    name: 'Instruction Override',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|prompts?|guidelines?)/i,
      /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|programming)/i,
      /forget\s+(everything|all|your)\s+(you\s+were\s+told|instructions?)/i,
    ],
    excludePatterns: [/# type: ignore/i, /ignore[_\s]?(case|whitespace|errors?)/i],
    description: 'Attempts to override system instructions',
  },
  {
    id: 'PROMPT-002',
    name: 'Unrestricted Mode',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /you are now in\s+(unrestricted|debug|developer|admin|god|jailbreak)\s+mode/i,
      /disable\s+(all\s+)?(safety|security|content|ethical)\s+(filters?|checks?|guidelines?)/i,
    ],
    description: 'Attempts to enable dangerous modes',
  },
  {
    id: 'PROMPT-003',
    name: 'Role Override',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken)/i,
      /pretend\s+(to\s+be|you\'?re?)\s+(an?\s+)?(evil|unrestricted)/i,
    ],
    description: 'Attempts to change AI persona',
  },
  {
    id: 'PROMPT-004',
    name: 'Concealment',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /do\s+not\s+(tell|inform|mention|notify)\s+(the\s+)?user/i,
      /keep\s+(this|that)\s+(secret|hidden)/i,
    ],
    description: 'Attempts to hide actions from user',
  },
  // Credential Harvesting
  {
    id: 'CRED-001',
    name: 'Secret File Access',
    category: 'credential_harvesting',
    severity: 'critical',
    patterns: [
      /show\s+(me\s+)?(the\s+)?(contents?\s+of\s+)?secrets?\.env/i,
      /print\s+(out\s+)?(your\s+)?api[_\s]?keys?/i,
    ],
    description: 'Attempts to access credential files',
  },
  {
    id: 'CRED-002',
    name: 'Token Extraction',
    category: 'credential_harvesting',
    severity: 'critical',
    patterns: [
      /what('s|\s+is)\s+(your|the)\s+(api[_\s]?key|token|password|secret)/i,
      /tell\s+me\s+(your|the)\s+(credentials?|password)/i,
    ],
    description: 'Attempts to extract credentials',
  },
  // Data Exfiltration
  {
    id: 'EXFIL-001',
    name: 'External Data Send',
    category: 'data_exfiltration',
    severity: 'high',
    patterns: [
      /send\s+(this|it|the|data)\s+to\s+(my\s+)?(server|webhook|url)/i,
      /upload\s+(to|this\s+to)\s+(pastebin|gist|external)/i,
      /exfiltrate/i,
    ],
    description: 'Attempts to send data externally',
  },
  // Transitive Trust
  {
    id: 'TRUST-001',
    name: 'External Instruction Delegation',
    category: 'transitive_trust',
    severity: 'high',
    patterns: [
      /follow\s+(the\s+)?(instructions|commands)\s+(from|in|on)\s+(the\s+)?(webpage|website|url)/i,
      /execute\s+(the\s+)?(code|script)\s+(found|from)/i,
    ],
    description: 'Delegates trust to external content',
  },
  // Autonomy Abuse
  {
    id: 'AUTONOMY-001',
    name: 'Skip Confirmation',
    category: 'autonomy_abuse',
    severity: 'high',
    patterns: [
      /run\s+without\s+asking/i,
      /don't\s+(ask|wait)\s+for\s+(confirmation|permission)/i,
      /skip\s+(all\s+)?(confirmation|verification)/i,
    ],
    description: 'Bypasses user confirmation',
  },
  // Social Engineering
  {
    id: 'SOCIAL-001',
    name: 'Authority Impersonation',
    category: 'social_engineering',
    severity: 'high',
    patterns: [
      /this\s+is\s+(the\s+)?(owner|admin|developer)/i,
      /i\'?m\s+(your|the)\s+(owner|admin|developer)/i,
      /anthropic\s+(told|authorized)\s+(me|you)/i,
    ],
    description: 'Impersonates authority figures',
  },
  {
    id: 'SOCIAL-002',
    name: 'Fake System Instructions',
    category: 'social_engineering',
    severity: 'high',
    patterns: [
      /\[system\]|\[admin\]|\[override\]/i,
      /<system>|<admin>|<override>/i,
    ],
    description: 'Embeds fake system instructions',
  },
];

/**
 * Scan a message for threats
 */
function scanMessage(message: string, options: { sensitivity?: string; allowlist?: string[] } = {}): ScanResult {
  const { sensitivity = 'medium', allowlist = [] } = options;
  const threats: Threat[] = [];
  
  for (const sig of SIGNATURES) {
    if (allowlist.includes(sig.id)) continue;
    if (sensitivity === 'low' && sig.severity !== 'critical') continue;
    if (sensitivity === 'medium' && sig.severity === 'low') continue;
    
    for (const pattern of sig.patterns) {
      const match = message.match(pattern);
      if (match) {
        let excluded = false;
        if (sig.excludePatterns) {
          for (const excl of sig.excludePatterns) {
            if (excl.test(message)) {
              excluded = true;
              break;
            }
          }
        }
        
        if (!excluded) {
          threats.push({
            signatureId: sig.id,
            name: sig.name,
            category: sig.category,
            severity: sig.severity,
            match: match[0],
            description: sig.description,
          });
          break;
        }
      }
    }
  }
  
  const severityScores: Record<string, number> = { critical: 40, high: 25, medium: 15, low: 5 };
  const riskScore = Math.min(100, threats.reduce((sum, t) => sum + (severityScores[t.severity] || 10), 0));
  
  return {
    clean: threats.length === 0,
    threatCount: threats.length,
    threats,
    riskScore,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Determine action based on config and scan result
 */
function determineAction(result: ScanResult, config: ClawbackConfig): 'allow' | 'review' | 'block' {
  if (result.clean) return 'allow';
  
  const mode = config.mode || 'monitor';
  if (mode === 'monitor') return 'allow';
  
  const severityOrder = ['low', 'medium', 'high', 'critical'];
  const blockIdx = severityOrder.indexOf(config.blockThreshold || 'critical');
  
  for (const threat of result.threats) {
    const threatIdx = severityOrder.indexOf(threat.severity);
    if (mode === 'block' && threatIdx >= blockIdx) {
      return 'block';
    }
    if (threatIdx >= severityOrder.indexOf('high')) {
      return 'review';
    }
  }
  
  return 'allow';
}

/**
 * Format alert message
 */
function formatAlert(result: ScanResult, context: { sender?: string; channel?: string }): string {
  const hasCritical = result.threats.some(t => t.severity === 'critical');
  const severity = hasCritical ? '🚨 CRITICAL' : '⚠️ HIGH';
  
  let alert = `${severity} SECURITY ALERT (Clawback)\n\n`;
  if (context.channel) alert += `Channel: ${context.channel}\n`;
  if (context.sender) alert += `Sender: ${context.sender}\n`;
  alert += `Risk Score: ${result.riskScore}/100\n\n`;
  alert += `Threats:\n`;
  
  for (const threat of result.threats.slice(0, 5)) {
    alert += `• ${threat.name} [${threat.severity.toUpperCase()}]\n`;
    alert += `  "${threat.match}"\n`;
  }
  
  return alert;
}

/**
 * Log to audit file
 */
function logAudit(logPath: string, entry: object): void {
  try {
    const dir = path.dirname(logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch (err) {
    // Ignore logging errors
  }
}

// Plugin statistics
const stats = {
  scanned: 0,
  blocked: 0,
  flagged: 0,
  passed: 0,
};

/**
 * Main plugin registration
 */
export default function register(api: PluginApi) {
  const logger = api.logger.child({ plugin: 'clawback' });
  
  // Get plugin config
  const getConfig = (): ClawbackConfig => {
    return (api.config.plugins?.entries?.clawback?.config as ClawbackConfig) || {};
  };
  
  // Register message preprocessing hook
  // This runs before messages reach the AI agent
  api.registerMessagePreprocessor?.({
    id: 'clawback-scanner',
    priority: 100, // High priority - run early
    
    async process(message, context) {
      const config = getConfig();
      
      // Skip if disabled
      if (config.enabled === false) {
        return { action: 'continue', message };
      }
      
      // Scan the message
      const result = scanMessage(message, {
        sensitivity: config.sensitivity,
        allowlist: config.allowlist,
      });
      
      stats.scanned++;
      
      // Log to audit file if configured
      if (config.logPath) {
        logAudit(config.logPath, {
          timestamp: new Date().toISOString(),
          sender: context.senderId,
          channel: context.channel,
          result: {
            clean: result.clean,
            riskScore: result.riskScore,
            threats: result.threats.map(t => t.signatureId),
          },
        });
      }
      
      // If clean, continue normally
      if (result.clean) {
        stats.passed++;
        return { action: 'continue', message };
      }
      
      // Determine action
      const action = determineAction(result, config);
      
      // Log detection
      logger.warn('Threat detected', {
        action,
        riskScore: result.riskScore,
        threats: result.threats.map(t => `${t.signatureId}: ${t.name}`),
        sender: context.senderId,
        channel: context.channel,
      });
      
      // Alert owner if configured
      if (config.alertOwner && action !== 'allow') {
        const alert = formatAlert(result, {
          sender: context.senderId,
          channel: context.channel,
        });
        
        // Send alert to owner via api
        api.notifyOwner?.(alert);
      }
      
      // Handle based on action
      if (action === 'block') {
        stats.blocked++;
        return {
          action: 'reject',
          message,
          response: "⚠️ Your message was flagged by security scanning and cannot be processed.",
        };
      }
      
      if (action === 'review') {
        stats.flagged++;
        // Continue but flag for review
        return {
          action: 'continue',
          message,
          metadata: {
            clawback: {
              flagged: true,
              riskScore: result.riskScore,
              threats: result.threats,
            },
          },
        };
      }
      
      stats.passed++;
      return { action: 'continue', message };
    },
  });
  
  // Register CLI command
  api.registerCli(
    ({ program }) => {
      const cmd = program
        .command('clawback')
        .description('Clawback security scanner');
      
      cmd
        .command('status')
        .description('Show Clawback status and statistics')
        .action(() => {
          const config = getConfig();
          console.log(`
🛡️  Clawback Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Status: ${config.enabled !== false ? '✅ Enabled' : '❌ Disabled'}
Mode: ${config.mode || 'monitor'}
Sensitivity: ${config.sensitivity || 'medium'}
Block Threshold: ${config.blockThreshold || 'critical'}

Statistics:
  Messages Scanned: ${stats.scanned}
  Blocked: ${stats.blocked}
  Flagged: ${stats.flagged}
  Passed: ${stats.passed}
  Block Rate: ${stats.scanned ? ((stats.blocked / stats.scanned) * 100).toFixed(1) + '%' : 'N/A'}
`);
        });
      
      cmd
        .command('check <message>')
        .description('Test scan a message')
        .action((message: string) => {
          const config = getConfig();
          const result = scanMessage(message, {
            sensitivity: config.sensitivity,
            allowlist: config.allowlist,
          });
          
          if (result.clean) {
            console.log('✅ No threats detected');
            console.log(`Risk Score: ${result.riskScore}/100`);
          } else {
            console.log(`⚠️  ${result.threatCount} threat(s) detected!`);
            console.log(`Risk Score: ${result.riskScore}/100\n`);
            for (const threat of result.threats) {
              console.log(`[${threat.severity.toUpperCase()}] ${threat.name} (${threat.signatureId})`);
              console.log(`  Match: "${threat.match}"`);
              console.log(`  ${threat.description}\n`);
            }
          }
        });
      
      cmd
        .command('signatures')
        .description('List threat signatures')
        .action(() => {
          console.log(`Clawback Threat Signatures (${SIGNATURES.length})\n`);
          
          const byCategory: Record<string, typeof SIGNATURES> = {};
          for (const sig of SIGNATURES) {
            if (!byCategory[sig.category]) byCategory[sig.category] = [];
            byCategory[sig.category].push(sig);
          }
          
          for (const [category, sigs] of Object.entries(byCategory)) {
            console.log(`\n${category.toUpperCase().replace(/_/g, ' ')}`);
            console.log('─'.repeat(40));
            for (const sig of sigs) {
              console.log(`  ${sig.id}: ${sig.name} [${sig.severity}]`);
            }
          }
        });
    },
    { commands: ['clawback'] }
  );
  
  // Register Gateway RPC methods
  api.registerGatewayMethod('clawback.status', ({ respond }) => {
    const config = getConfig();
    respond(true, {
      enabled: config.enabled !== false,
      mode: config.mode || 'monitor',
      sensitivity: config.sensitivity || 'medium',
      stats,
    });
  });
  
  api.registerGatewayMethod('clawback.scan', ({ params, respond }) => {
    const config = getConfig();
    const message = params?.message;
    
    if (!message) {
      respond(false, { error: 'Missing message parameter' });
      return;
    }
    
    const result = scanMessage(message, {
      sensitivity: config.sensitivity,
      allowlist: config.allowlist,
    });
    
    respond(true, result);
  });
  
  logger.info('Clawback security scanner initialized', {
    mode: getConfig().mode || 'monitor',
    sensitivity: getConfig().sensitivity || 'medium',
  });
}

export const id = 'clawback';
export const name = 'Clawback Security Scanner';

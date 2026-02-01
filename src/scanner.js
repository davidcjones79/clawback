/**
 * Clawback Scanner
 * Core scanning functionality for threat detection
 * 
 * Multi-engine detection inspired by Cisco AI Defense Skill Scanner
 * https://github.com/cisco-ai-defense/skill-scanner
 */

const fs = require('fs');
const path = require('path');
const { signatures } = require('./signatures');
const { scanSkillDirectory, scanSkillMd, scanPythonFile } = require('./skill-scanner');
const { calculateRiskScore, parseSimpleYaml } = require('./utils');

/**
 * Scan a message for prompt injection attempts
 * @param {string} message - The message to scan
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
function scanMessage(message, options = {}) {
  const { sensitivity = 'medium', allowlist = [] } = options;
  const threats = [];
  
  for (const sig of signatures) {
    // Skip if signature is allowlisted
    if (allowlist.includes(sig.id)) continue;
    
    // Skip file-specific signatures for message scanning
    if (sig.fileTypes) continue;
    
    // Adjust for sensitivity
    if (sensitivity === 'low' && sig.severity !== 'critical') continue;
    if (sensitivity === 'medium' && sig.severity === 'low') continue;
    
    for (const pattern of sig.patterns) {
      const match = message.match(pattern);
      if (match) {
        // Check exclusions
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
            index: match.index,
            description: sig.description,
            remediation: sig.remediation || null,
          });
          break; // Only report each signature once per message
        }
      }
    }
  }
  
  return {
    clean: threats.length === 0,
    threatCount: threats.length,
    threats,
    riskScore: calculateRiskScore(threats),
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Scan an OpenClaw config file for security issues
 * Expanded auditing inspired by Cisco's security best practices
 * @param {object} config - The parsed config object
 * @returns {object} Audit results
 */
function auditConfig(config) {
  const issues = [];
  
  // ============================================================================
  // EXECUTION SECURITY
  // ============================================================================
  
  if (config.exec?.security === 'full') {
    issues.push({
      id: 'CONFIG-001',
      severity: 'high',
      message: 'exec.security is set to "full" - consider using "allowlist"',
      path: 'exec.security',
      remediation: 'Use exec.security = "allowlist" with explicit command allowlist',
    });
  }
  
  if (config.exec?.elevated === true) {
    issues.push({
      id: 'CONFIG-002',
      severity: 'critical',
      message: 'Elevated (sudo) execution is enabled globally',
      path: 'exec.elevated',
      remediation: 'Disable elevated execution or use per-command allowlist',
    });
  }
  
  // ============================================================================
  // BROWSER SECURITY
  // ============================================================================
  
  if (config.browser?.target === 'host' && !config.browser?.profile) {
    issues.push({
      id: 'CONFIG-003',
      severity: 'medium',
      message: 'Browser target is "host" without profile isolation',
      path: 'browser.target',
      remediation: 'Use browser.profile to isolate browser sessions',
    });
  }
  
  // ============================================================================
  // AUTHENTICATION
  // ============================================================================
  
  if (!config.gateway?.authToken && !config.gateway?.tailscale) {
    issues.push({
      id: 'CONFIG-004',
      severity: 'critical',
      message: 'No authentication configured for gateway',
      path: 'gateway',
      remediation: 'Set gateway.authToken or use Tailscale authentication',
    });
  }
  
  // Check for weak auth token
  if (config.gateway?.authToken && config.gateway.authToken.length < 32) {
    issues.push({
      id: 'CONFIG-005',
      severity: 'high',
      message: 'Auth token is too short (should be at least 32 characters)',
      path: 'gateway.authToken',
      remediation: 'Use a cryptographically secure token of at least 32 characters',
    });
  }
  
  // ============================================================================
  // CHANNEL SECURITY
  // ============================================================================
  
  if (config.channels && !config.channels.some(c => c.ownerNumbers?.length > 0)) {
    issues.push({
      id: 'CONFIG-006',
      severity: 'medium',
      message: 'No owner numbers configured for any channel',
      path: 'channels',
      remediation: 'Set ownerNumbers to restrict who can interact with the agent',
    });
  }
  
  // Check for channels without allowlists in group settings
  if (config.channels) {
    for (const channel of config.channels) {
      if (channel.groups?.enabled && !channel.groups?.allowlist?.length) {
        issues.push({
          id: 'CONFIG-007',
          severity: 'medium',
          message: `Channel "${channel.type}" has groups enabled without allowlist`,
          path: `channels.${channel.type}.groups`,
          remediation: 'Set groups.allowlist to restrict which groups the agent can join',
        });
      }
    }
  }
  
  // ============================================================================
  // TOOL & SKILL SECURITY
  // ============================================================================
  
  if (config.tools?.browser?.enabled && !config.tools?.browser?.allowlist) {
    issues.push({
      id: 'CONFIG-008',
      severity: 'medium',
      message: 'Browser tool enabled without URL allowlist',
      path: 'tools.browser',
      remediation: 'Set tools.browser.allowlist to restrict accessible URLs',
    });
  }
  
  // Check for skills from untrusted sources
  if (config.skills) {
    for (const skill of config.skills) {
      if (skill.source && !skill.source.startsWith('https://')) {
        issues.push({
          id: 'CONFIG-009',
          severity: 'high',
          message: `Skill "${skill.name}" loaded from non-HTTPS source`,
          path: `skills.${skill.name}`,
          remediation: 'Only load skills from HTTPS sources',
        });
      }
    }
  }
  
  // ============================================================================
  // NETWORK EXPOSURE
  // ============================================================================
  
  if (config.gateway?.host === '0.0.0.0' && !config.gateway?.authToken) {
    issues.push({
      id: 'CONFIG-010',
      severity: 'critical',
      message: 'Gateway bound to all interfaces without authentication',
      path: 'gateway.host',
      remediation: 'Either bind to localhost or enable authentication',
    });
  }
  
  // ============================================================================
  // LOGGING & AUDIT
  // ============================================================================
  
  if (config.logging?.level === 'debug' || config.logging?.includeSecrets) {
    issues.push({
      id: 'CONFIG-011',
      severity: 'medium',
      message: 'Debug logging may expose sensitive information',
      path: 'logging',
      remediation: 'Use "info" level in production, never enable includeSecrets',
    });
  }
  
  // ============================================================================
  // MODEL SECURITY
  // ============================================================================
  
  if (config.model?.thinking === 'stream' && config.channels?.some(c => c.type === 'telegram' || c.type === 'discord')) {
    issues.push({
      id: 'CONFIG-012',
      severity: 'low',
      message: 'Streaming thinking output to public channels may leak reasoning',
      path: 'model.thinking',
      remediation: 'Use thinking = "hidden" for public-facing channels',
    });
  }
  
  return {
    secure: issues.length === 0,
    issueCount: issues.length,
    issues,
    auditedAt: new Date().toISOString(),
  };
}

/**
 * Scan an OpenClaw installation directory
 * @param {string} openclawPath - Path to ~/.openclaw or similar
 * @returns {object} Scan results
 */
function scanOpenClawDirectory(openclawPath) {
  const results = {
    path: openclawPath,
    scannedAt: new Date().toISOString(),
    configAudit: null,
    skillScans: [],
    sensitiveFiles: [],
    issues: [],
  };
  
  if (!fs.existsSync(openclawPath)) {
    throw new Error(`Path not found: ${openclawPath}`);
  }
  
  // Look for config files
  const configFiles = ['config.yaml', 'config.yml', 'config.json'];
  for (const configFile of configFiles) {
    const configPath = path.join(openclawPath, configFile);
    if (fs.existsSync(configPath)) {
      try {
        const content = fs.readFileSync(configPath, 'utf8');
        let config;
        
        if (configFile.endsWith('.json')) {
          config = JSON.parse(content);
        } else {
          // YAML parsing
          config = parseSimpleYaml(content);
        }
        
        results.configAudit = auditConfig(config);
        results.configFile = configFile;
        break; // Use first config found
      } catch (err) {
        results.issues.push({
          type: 'parse_error',
          file: configFile,
          message: err.message,
        });
      }
    }
  }
  
  // Scan for sensitive files
  const sensitivePatterns = ['.env', 'secrets', 'credentials', 'private', '.pem', '.key'];
  
  function scanDir(dir, depth = 0) {
    if (depth > 5) return; // Limit recursion
    
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          // Skip node_modules, .git, etc
          if (!['node_modules', '.git', 'vendor'].includes(entry.name)) {
            scanDir(fullPath, depth + 1);
          }
        } else {
          const lower = entry.name.toLowerCase();
          if (sensitivePatterns.some(p => lower.includes(p))) {
            results.sensitiveFiles.push({
              path: fullPath.replace(openclawPath, ''),
              name: entry.name,
            });
          }
        }
      }
    } catch (err) {
      // Permission denied, etc
    }
  }
  
  scanDir(openclawPath);
  
  // Scan skills directory if it exists
  const skillsPath = path.join(openclawPath, 'skills');
  if (fs.existsSync(skillsPath)) {
    try {
      const skillDirs = fs.readdirSync(skillsPath, { withFileTypes: true });
      for (const skillDir of skillDirs) {
        if (skillDir.isDirectory()) {
          const skillPath = path.join(skillsPath, skillDir.name);
          try {
            const skillResult = scanSkillDirectory(skillPath);
            results.skillScans.push({
              skill: skillDir.name,
              ...skillResult,
            });
          } catch (err) {
            results.issues.push({
              type: 'skill_scan_error',
              skill: skillDir.name,
              message: err.message,
            });
          }
        }
      }
    } catch (err) {
      results.issues.push({
        type: 'skills_dir_error',
        message: err.message,
      });
    }
  }
  
  // Calculate overall risk
  let totalThreats = 0;
  let criticalCount = 0;
  
  if (results.configAudit) {
    totalThreats += results.configAudit.issueCount;
    criticalCount += results.configAudit.issues.filter(i => i.severity === 'critical').length;
  }
  
  for (const skill of results.skillScans) {
    totalThreats += skill.summary?.totalThreats || 0;
    criticalCount += skill.summary?.bySeverity?.critical || 0;
  }
  
  results.summary = {
    totalThreats,
    criticalCount,
    sensitiveFileCount: results.sensitiveFiles.length,
    skillsScanned: results.skillScans.length,
  };
  
  results.riskScore = Math.min(100,
    (criticalCount * 40) +
    ((totalThreats - criticalCount) * 10) +
    (results.sensitiveFiles.length * 5)
  );
  
  results.clean = totalThreats === 0 && results.sensitiveFiles.length === 0;
  
  return results;
}

/**
 * Scan session logs for suspicious patterns
 * @param {string} logPath - Path to session log directory
 * @returns {Promise<object>} Audit results
 */
async function auditSessionLogs(logPath) {
  const results = {
    path: logPath,
    scannedAt: new Date().toISOString(),
    suspiciousMessages: [],
    stats: {
      totalMessages: 0,
      flaggedMessages: 0,
    },
  };
  
  if (!fs.existsSync(logPath)) {
    return { ...results, error: 'Path not found' };
  }
  
  // Find .jsonl files
  const files = fs.readdirSync(logPath).filter(f => f.endsWith('.jsonl'));
  
  for (const file of files) {
    const filePath = path.join(logPath, file);
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.trim().split('\n');
      
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          results.stats.totalMessages++;
          
          // Extract message content
          const messageContent = entry.content || entry.message || '';
          if (typeof messageContent !== 'string') continue;
          
          // Scan for threats
          const scanResult = scanMessage(messageContent, { sensitivity: 'high' });
          
          if (!scanResult.clean) {
            results.stats.flaggedMessages++;
            results.suspiciousMessages.push({
              file,
              timestamp: entry.timestamp || entry.created_at,
              role: entry.role,
              threats: scanResult.threats,
              preview: messageContent.slice(0, 100) + (messageContent.length > 100 ? '...' : ''),
            });
          }
        } catch (parseErr) {
          // Skip malformed JSON lines
        }
      }
    } catch (err) {
      results.errors = results.errors || [];
      results.errors.push({ file, error: err.message });
    }
  }
  
  results.riskScore = Math.min(100, results.stats.flaggedMessages * 20);
  results.clean = results.stats.flaggedMessages === 0;
  
  return results;
}

module.exports = {
  scanMessage,
  auditConfig,
  scanOpenClawDirectory,
  auditSessionLogs,
  scanSkillDirectory,
  signatures,
};

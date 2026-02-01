/**
 * ClawGuard Scanner
 * Core scanning functionality for threat detection
 */

const { signatures } = require('./signatures');

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
    
    // Adjust for sensitivity
    if (sensitivity === 'low' && sig.severity !== 'critical') continue;
    if (sensitivity === 'medium' && sig.severity === 'low') continue;
    
    for (const pattern of sig.patterns) {
      const match = message.match(pattern);
      if (match) {
        threats.push({
          signatureId: sig.id,
          name: sig.name,
          category: sig.category,
          severity: sig.severity,
          match: match[0],
          index: match.index,
          description: sig.description,
        });
        break; // Only report each signature once per message
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
 * Calculate a risk score from 0-100
 */
function calculateRiskScore(threats) {
  if (threats.length === 0) return 0;
  
  const severityScores = {
    critical: 40,
    high: 25,
    medium: 15,
    low: 5,
  };
  
  let score = 0;
  for (const threat of threats) {
    score += severityScores[threat.severity] || 10;
  }
  
  return Math.min(100, score);
}

/**
 * Scan an OpenClaw config file for security issues
 * @param {object} config - The parsed config object
 * @returns {object} Audit results
 */
function auditConfig(config) {
  const issues = [];
  
  // Check for overly permissive settings
  if (config.exec?.security === 'full') {
    issues.push({
      id: 'CONFIG-001',
      severity: 'high',
      message: 'exec.security is set to "full" - consider using "allowlist"',
      path: 'exec.security',
    });
  }
  
  if (config.browser?.target === 'host' && !config.browser?.profile) {
    issues.push({
      id: 'CONFIG-002',
      severity: 'medium',
      message: 'Browser target is "host" without profile isolation',
      path: 'browser.target',
    });
  }
  
  if (!config.gateway?.authToken && !config.gateway?.tailscale) {
    issues.push({
      id: 'CONFIG-003',
      severity: 'critical',
      message: 'No authentication configured for gateway',
      path: 'gateway',
    });
  }
  
  if (config.channels && !config.channels.some(c => c.ownerNumbers?.length > 0)) {
    issues.push({
      id: 'CONFIG-004',
      severity: 'medium',
      message: 'No owner numbers configured for any channel',
      path: 'channels',
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
 * Scan session logs for suspicious patterns
 * @param {string} logPath - Path to session log directory
 * @returns {Promise<object>} Audit results
 */
async function auditSessionLogs(logPath) {
  // TODO: Implement session log scanning
  return {
    implemented: false,
    message: 'Session log auditing coming in v0.2.0',
  };
}

module.exports = {
  scanMessage,
  auditConfig,
  auditSessionLogs,
  signatures,
};

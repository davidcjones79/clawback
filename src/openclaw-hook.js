#!/usr/bin/env node
/**
 * ClawGuard OpenClaw Integration Hook
 * 
 * This module provides integration points for OpenClaw:
 * 1. Pre-message scanning (before AI processes)
 * 2. Audit logging for sensitive actions
 * 3. Alert dispatching (Telegram, email, etc.)
 * 
 * Usage:
 *   Integrate into your OpenClaw heartbeat or as a preprocessing step
 */

const { ClawGuardScanner } = require('./scanner');
const fs = require('fs');
const path = require('path');

// Alert configuration (customize for your setup)
const ALERT_CONFIG = {
  telegram: {
    enabled: true,
    // Will use OpenClaw's message tool
  },
  email: {
    enabled: true,
    to: 'david@sonomait.com',
    // Will use gog CLI
  },
  log: {
    enabled: true,
    path: path.join(__dirname, '..', 'logs', 'alerts.jsonl')
  }
};

class ClawGuardHook {
  constructor(options = {}) {
    this.scanner = new ClawGuardScanner({
      minSeverity: options.minSeverity || 'low'
    });
    this.config = { ...ALERT_CONFIG, ...options.alerts };
  }

  /**
   * Scan incoming message before processing
   * @param {string} message - The message content
   * @param {object} context - Message context (sender, channel, etc.)
   * @returns {object} Scan results with recommendation
   */
  scanMessage(message, context = {}) {
    const results = this.scanner.scan(message, context);
    
    // Add recommendation
    results.recommendation = this.getRecommendation(results);
    
    return results;
  }

  /**
   * Get recommendation based on scan results
   */
  getRecommendation(results) {
    if (results.blocked) {
      return {
        action: 'reject',
        reason: `Blocked by ClawGuard: ${results.threats[0]?.name}`,
        respond: true,
        response: "I've detected potentially malicious content in your message and cannot process it for security reasons."
      };
    }
    
    if (results.summary.critical > 0 || results.summary.high > 0) {
      return {
        action: 'review',
        reason: `High-severity threat detected: ${results.threats[0]?.name}`,
        respond: false,
        alertOwner: true
      };
    }
    
    if (results.summary.medium > 0) {
      return {
        action: 'proceed_with_caution',
        reason: `Medium-severity pattern detected: ${results.threats[0]?.name}`,
        respond: false,
        alertOwner: true
      };
    }
    
    return {
      action: 'proceed',
      reason: null,
      respond: false,
      alertOwner: false
    };
  }

  /**
   * Generate alert message for detected threats
   */
  formatAlert(results, context = {}) {
    const severity = results.summary.critical > 0 ? '🚨 CRITICAL' :
                     results.summary.high > 0 ? '⚠️ HIGH' :
                     '⚡ MEDIUM';
    
    let alert = `${severity} SECURITY ALERT\n\n`;
    alert += `Source: ${context.source || 'unknown'}\n`;
    alert += `Sender: ${context.sender || 'unknown'}\n`;
    alert += `Time: ${results.timestamp}\n\n`;
    
    alert += `Threats Detected:\n`;
    for (const threat of results.threats.slice(0, 3)) {
      alert += `• ${threat.name} (${threat.severity})\n`;
      alert += `  Pattern: "${threat.matches[0]}"\n`;
    }
    
    if (results.blocked) {
      alert += `\n🚫 Message was BLOCKED`;
    }
    
    return alert;
  }

  /**
   * Log alert to file
   */
  logAlert(results, context = {}) {
    if (!this.config.log.enabled) return;
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      results,
      context,
      alert_sent: true
    };
    
    const logDir = path.dirname(this.config.log.path);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    
    fs.appendFileSync(this.config.log.path, JSON.stringify(logEntry) + '\n');
  }
}

/**
 * Quick scan function for simple usage
 */
function quickScan(text, context = {}) {
  const hook = new ClawGuardHook();
  return hook.scanMessage(text, context);
}

/**
 * Check if message should be processed
 * Returns { safe: boolean, reason?: string, alert?: string }
 */
function checkMessage(text, context = {}) {
  const hook = new ClawGuardHook();
  const results = hook.scanMessage(text, context);
  
  return {
    safe: !results.blocked && results.summary.critical === 0 && results.summary.high === 0,
    blocked: results.blocked,
    threats: results.threats.length,
    severity: results.summary.critical > 0 ? 'critical' :
              results.summary.high > 0 ? 'high' :
              results.summary.medium > 0 ? 'medium' :
              results.summary.low > 0 ? 'low' : 'none',
    reason: results.threats[0]?.name,
    alert: results.threats.length > 0 ? hook.formatAlert(results, context) : null
  };
}

// CLI for testing
if (require.main === module) {
  const args = process.argv.slice(2);
  const text = args.join(' ') || 'Test message';
  
  console.log('ClawGuard OpenClaw Hook - Test Mode\n');
  console.log(`Scanning: "${text}"\n`);
  
  const result = checkMessage(text, { source: 'test', sender: 'cli' });
  console.log('Result:', JSON.stringify(result, null, 2));
  
  if (result.alert) {
    console.log('\n--- Alert Message ---');
    console.log(result.alert);
  }
}

module.exports = {
  ClawGuardHook,
  quickScan,
  checkMessage
};

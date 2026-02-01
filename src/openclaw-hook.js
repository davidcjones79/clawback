#!/usr/bin/env node
/**
 * Clawback OpenClaw Integration Hook
 * 
 * This module provides integration points for OpenClaw:
 * 1. Pre-message scanning (before AI processes)
 * 2. Alert formatting for notifications
 * 3. Quick check function for simple usage
 * 
 * Usage:
 *   const { checkMessage } = require('clawback/src/openclaw-hook');
 *   const result = checkMessage('user input here');
 *   if (!result.safe) { // handle threat }
 */

const { scanMessage } = require('./scanner');

/**
 * Check if a message should be processed
 * @param {string} text - The message to check
 * @param {object} context - Optional context (sender, channel, etc.)
 * @returns {object} Check result
 */
function checkMessage(text, context = {}) {
  const results = scanMessage(text, { sensitivity: 'high' });
  
  // Determine overall safety
  const hasCritical = results.threats.some(t => t.severity === 'critical');
  const hasHigh = results.threats.some(t => t.severity === 'high');
  
  return {
    safe: results.clean,
    blocked: hasCritical,
    threatCount: results.threatCount,
    riskScore: results.riskScore,
    severity: hasCritical ? 'critical' :
              hasHigh ? 'high' :
              results.threatCount > 0 ? 'medium' : 'none',
    reason: results.threats[0]?.name || null,
    threats: results.threats,
    alert: results.threatCount > 0 ? formatAlert(results, context) : null,
    recommendation: getRecommendation(results),
  };
}

/**
 * Get recommendation based on scan results
 */
function getRecommendation(results) {
  const hasCritical = results.threats.some(t => t.severity === 'critical');
  const hasHigh = results.threats.some(t => t.severity === 'high');
  const hasMedium = results.threats.some(t => t.severity === 'medium');
  
  if (hasCritical) {
    return {
      action: 'reject',
      reason: `Critical threat: ${results.threats[0]?.name}`,
      respond: true,
      response: "I've detected potentially malicious content and cannot process this request.",
    };
  }
  
  if (hasHigh) {
    return {
      action: 'review',
      reason: `High-severity threat: ${results.threats[0]?.name}`,
      alertOwner: true,
    };
  }
  
  if (hasMedium) {
    return {
      action: 'proceed_with_caution',
      reason: `Medium-severity pattern: ${results.threats[0]?.name}`,
      alertOwner: true,
    };
  }
  
  return {
    action: 'proceed',
    reason: null,
    alertOwner: false,
  };
}

/**
 * Format alert message for notifications
 */
function formatAlert(results, context = {}) {
  const hasCritical = results.threats.some(t => t.severity === 'critical');
  const hasHigh = results.threats.some(t => t.severity === 'high');
  
  const severity = hasCritical ? '🚨 CRITICAL' :
                   hasHigh ? '⚠️ HIGH' : '⚡ MEDIUM';
  
  let alert = `${severity} SECURITY ALERT\n\n`;
  if (context.source) alert += `Source: ${context.source}\n`;
  if (context.sender) alert += `Sender: ${context.sender}\n`;
  alert += `Time: ${results.scannedAt}\n`;
  alert += `Risk Score: ${results.riskScore}/100\n\n`;
  
  alert += `Threats Detected:\n`;
  for (const threat of results.threats.slice(0, 5)) {
    alert += `• ${threat.name} [${threat.severity.toUpperCase()}]\n`;
    alert += `  Match: "${threat.match}"\n`;
  }
  
  if (results.threats.length > 5) {
    alert += `\n... and ${results.threats.length - 5} more`;
  }
  
  return alert;
}

/**
 * Quick scan with simple boolean return
 * @param {string} text - Text to scan
 * @returns {boolean} True if safe, false if threats detected
 */
function isSafe(text) {
  const result = scanMessage(text);
  return result.clean;
}

// CLI for testing
if (require.main === module) {
  const args = process.argv.slice(2);
  const text = args.filter(a => !a.startsWith('--')).join(' ') || 'Test message';
  
  console.log('Clawback OpenClaw Hook - Test Mode\n');
  console.log(`Scanning: "${text}"\n`);
  
  const result = checkMessage(text, { source: 'cli', sender: 'test' });
  console.log('Result:', JSON.stringify(result, null, 2));
  
  if (result.alert) {
    console.log('\n--- Alert Message ---');
    console.log(result.alert);
  }
  
  process.exit(result.safe ? 0 : 1);
}

module.exports = {
  checkMessage,
  formatAlert,
  isSafe,
  getRecommendation,
};

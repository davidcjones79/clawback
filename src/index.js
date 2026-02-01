/**
 * ClawGuard
 * Security scanner and threat detection for OpenClaw
 */

const { scanMessage, auditConfig, auditSessionLogs, signatures } = require('./scanner');

module.exports = {
  scanMessage,
  auditConfig,
  auditSessionLogs,
  signatures,
  version: '0.1.0',
};

/**
 * Clawback
 * Security scanner and threat detection for OpenClaw
 * 
 * Threat taxonomy inspired by Cisco AI Defense Skill Scanner
 * https://github.com/cisco-ai-defense/skill-scanner
 */

const { 
  scanMessage, 
  auditConfig, 
  scanOpenClawDirectory,
  auditSessionLogs,
  signatures 
} = require('./scanner');

const { 
  scanSkillMd, 
  scanPythonFile, 
  scanBashFile,
  scanSkillDirectory,
  parseFrontmatter 
} = require('./skill-scanner');

const {
  checkMessage,
  isSafe,
  formatAlert,
} = require('./openclaw-hook');

const {
  startServer,
  createRequestHandler,
} = require('./server');

const {
  calculateRiskScore,
  getLineNumber,
  parseSimpleYaml,
} = require('./utils');

module.exports = {
  // Core scanning
  scanMessage,
  auditConfig,
  scanOpenClawDirectory,
  auditSessionLogs,
  
  // Skill scanning
  scanSkillMd,
  scanPythonFile,
  scanBashFile,
  scanSkillDirectory,
  parseFrontmatter,
  
  // OpenClaw integration
  checkMessage,
  isSafe,
  formatAlert,
  
  // Server
  startServer,
  createRequestHandler,
  
  // Utilities
  calculateRiskScore,
  getLineNumber,
  parseSimpleYaml,
  
  // Signatures
  signatures,
  
  // Version
  version: '0.2.0',
};

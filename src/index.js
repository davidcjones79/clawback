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
  
  // Signatures
  signatures,
  
  // Version
  version: '0.2.0',
};

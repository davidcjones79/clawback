/**
 * Clawback Skill Scanner
 * 
 * Scans Agent Skill packages (SKILL.md + Python/Bash scripts) for threats.
 * Inspired by Cisco AI Defense Skill Scanner's architecture.
 * https://github.com/cisco-ai-defense/skill-scanner
 * 
 * Supports:
 * - OpenAI Codex Skills format
 * - Cursor Agent Skills format  
 * - OpenClaw Skills format
 * - AgentSkills.io specification
 */

const fs = require('fs');
const path = require('path');
const { signatures } = require('./signatures');
const { calculateRiskScore, getLineNumber } = require('./utils');

/**
 * Parse SKILL.md frontmatter (YAML between --- delimiters)
 */
function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};
  
  const yaml = match[1];
  const result = {};
  
  // Simple YAML parser for frontmatter
  for (const line of yaml.split('\n')) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim();
      let value = line.slice(colonIdx + 1).trim();
      
      // Handle arrays like [Read, Write]
      if (value.startsWith('[') && value.endsWith(']')) {
        value = value.slice(1, -1).split(',').map(s => s.trim());
      }
      result[key] = value;
    }
  }
  
  return result;
}

/**
 * Scan a SKILL.md file for threats
 */
function scanSkillMd(content, filePath = 'SKILL.md') {
  const threats = [];
  const frontmatter = parseFrontmatter(content);
  
  // Get the instruction content (after frontmatter)
  const instructionContent = content.replace(/^---\n[\s\S]*?\n---\n?/, '');
  
  // Check for vague or missing description
  if (frontmatter.description) {
    if (frontmatter.description.length < 20) {
      threats.push({
        signatureId: 'SKILL-001',
        name: 'Vague Description',
        category: 'social_engineering',
        severity: 'low',
        match: frontmatter.description,
        description: 'Skill description is too vague or short',
        file: filePath,
      });
    }
  } else {
    threats.push({
      signatureId: 'SKILL-002',
      name: 'Missing Description',
      category: 'social_engineering',
      severity: 'medium',
      match: '(no description)',
      description: 'Skill is missing a description',
      file: filePath,
    });
  }
  
  // Scan instruction content for prompt injection patterns
  for (const sig of signatures) {
    if (sig.category !== 'prompt_injection' && 
        sig.category !== 'transitive_trust' &&
        sig.category !== 'autonomy_abuse' &&
        sig.category !== 'social_engineering') continue;
    
    for (const pattern of sig.patterns) {
      const match = instructionContent.match(pattern);
      if (match) {
        // Check exclusions
        let excluded = false;
        if (sig.excludePatterns) {
          for (const excl of sig.excludePatterns) {
            if (excl.test(instructionContent)) {
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
            file: filePath,
            line: getLineNumber(instructionContent, match.index),
          });
          break;
        }
      }
    }
  }
  
  return {
    frontmatter,
    threats,
    allowedTools: frontmatter['allowed-tools'] || [],
  };
}

/**
 * Scan a Python file for code-level threats
 * Basic static analysis without full AST parsing
 */
function scanPythonFile(content, filePath) {
  const threats = [];
  const lines = content.split('\n');
  
  // Track imports for context
  const imports = new Set();
  const hasNetworkImport = /import\s+(requests|urllib|httpx|aiohttp|socket)/m.test(content);
  const hasSubprocessImport = /import\s+subprocess|from\s+subprocess/.test(content);
  
  // Extract imports
  for (const line of lines) {
    const importMatch = line.match(/^(?:import|from)\s+(\w+)/);
    if (importMatch) imports.add(importMatch[1]);
  }
  
  // Scan for code-level signatures
  for (const sig of signatures) {
    // Only scan code-relevant signatures
    if (!sig.fileTypes || !sig.fileTypes.includes('python')) continue;
    
    for (const pattern of sig.patterns) {
      let match;
      // Ensure 'g' flag is set without duplication
      const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
      const regex = new RegExp(pattern.source, flags);
      
      while ((match = regex.exec(content)) !== null) {
        // Check exclusions
        let excluded = false;
        if (sig.excludePatterns) {
          for (const excl of sig.excludePatterns) {
            if (excl.test(content)) {
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
            file: filePath,
            line: getLineNumber(content, match.index),
          });
        }
      }
    }
  }
  
  // Behavioral analysis: detect dangerous combinations
  // Inspired by Cisco's dataflow analysis approach
  
  // Pattern: Network import + credential file access
  if (hasNetworkImport) {
    const credFilePattern = /open\s*\([^)]*(?:\.env|\.aws|\.ssh|credentials|secret)/i;
    const credMatch = content.match(credFilePattern);
    if (credMatch) {
      threats.push({
        signatureId: 'BEHAVIOR-001',
        name: 'Credential File + Network',
        category: 'data_exfiltration',
        severity: 'critical',
        match: credMatch[0],
        description: 'Accesses credential files with network capability (potential exfiltration)',
        file: filePath,
        line: getLineNumber(content, credMatch.index),
      });
    }
  }
  
  // Pattern: os.environ harvesting + network
  if (hasNetworkImport && /os\.environ/.test(content)) {
    const envIterPattern = /os\.environ\.(items|keys|values)\s*\(\)|dict\(os\.environ\)/;
    const envMatch = content.match(envIterPattern);
    if (envMatch) {
      threats.push({
        signatureId: 'BEHAVIOR-002',
        name: 'Environment Harvesting + Network',
        category: 'data_exfiltration',
        severity: 'critical',
        match: envMatch[0],
        description: 'Iterates environment variables with network capability (credential theft)',
        file: filePath,
        line: getLineNumber(content, envMatch.index),
      });
    }
  }
  
  // Pattern: eval/exec + subprocess (extra dangerous)
  if (hasSubprocessImport && /\b(eval|exec)\s*\(/.test(content)) {
    threats.push({
      signatureId: 'BEHAVIOR-003',
      name: 'Eval + Subprocess',
      category: 'command_injection',
      severity: 'critical',
      match: 'eval/exec with subprocess',
      description: 'Combines eval/exec with subprocess (extremely dangerous)',
      file: filePath,
    });
  }
  
  // Pattern: Base64 decode + exec (obfuscated payload)
  if (/base64\.(b64)?decode/.test(content) && /\b(eval|exec)\s*\(/.test(content)) {
    threats.push({
      signatureId: 'BEHAVIOR-004',
      name: 'Base64 Decode + Exec',
      category: 'obfuscation',
      severity: 'critical',
      match: 'base64 decode → exec',
      description: 'Decodes and executes base64 payload (likely malicious)',
      file: filePath,
    });
  }
  
  // Pattern: Suspicious URLs
  const urlPattern = /https?:\/\/\S*(attacker|evil|malicious|c2\.|exfil)\S*/gi;
  let urlMatch;
  while ((urlMatch = urlPattern.exec(content)) !== null) {
    threats.push({
      signatureId: 'BEHAVIOR-005',
      name: 'Suspicious URL',
      category: 'data_exfiltration',
      severity: 'high',
      match: urlMatch[0],
      description: 'URL contains suspicious keywords',
      file: filePath,
      line: getLineNumber(content, urlMatch.index),
    });
  }
  
  return threats;
}

/**
 * Scan a Bash file for threats
 */
function scanBashFile(content, filePath) {
  const threats = [];
  
  // Dangerous patterns in bash
  const bashPatterns = [
    {
      id: 'BASH-001',
      name: 'Curl Pipe Shell',
      pattern: /curl\s+[^\|]+\|\s*(bash|sh|zsh)/gi,
      category: 'transitive_trust',
      severity: 'critical',
      description: 'Downloads and executes remote script',
    },
    {
      id: 'BASH-002', 
      name: 'Wget Execute',
      pattern: /wget\s+[^;]+;\s*(bash|sh|chmod)/gi,
      category: 'transitive_trust',
      severity: 'critical',
      description: 'Downloads and executes remote script',
    },
    {
      id: 'BASH-003',
      name: 'Eval Variable',
      pattern: /eval\s+.*\$/gi,
      category: 'command_injection',
      severity: 'high',
      description: 'Eval with variable expansion (injection risk)',
    },
    {
      id: 'BASH-004',
      name: 'Sudo NOPASSWD',
      pattern: /NOPASSWD/gi,
      category: 'tool_abuse',
      severity: 'high',
      description: 'Attempts to configure passwordless sudo',
    },
    {
      id: 'BASH-005',
      name: 'Reverse Shell',
      pattern: /\/dev\/tcp\/|nc\s+-[el]|bash\s+-i\s+>&/gi,
      category: 'command_injection',
      severity: 'critical',
      description: 'Reverse shell pattern detected',
    },
  ];
  
  for (const sig of bashPatterns) {
    let match;
    while ((match = sig.pattern.exec(content)) !== null) {
      threats.push({
        signatureId: sig.id,
        name: sig.name,
        category: sig.category,
        severity: sig.severity,
        match: match[0],
        description: sig.description,
        file: filePath,
        line: getLineNumber(content, match.index),
      });
    }
  }
  
  return threats;
}

/**
 * Scan an entire skill directory
 */
function scanSkillDirectory(skillPath) {
  const results = {
    path: skillPath,
    scannedAt: new Date().toISOString(),
    files: [],
    threats: [],
    summary: {
      totalFiles: 0,
      totalThreats: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategory: {},
    },
  };
  
  // Check if path exists
  if (!fs.existsSync(skillPath)) {
    throw new Error(`Path not found: ${skillPath}`);
  }
  
  const stat = fs.statSync(skillPath);
  const files = stat.isDirectory() 
    ? fs.readdirSync(skillPath, { recursive: true })
    : [path.basename(skillPath)];
  
  const basePath = stat.isDirectory() ? skillPath : path.dirname(skillPath);
  
  for (const file of files) {
    const filePath = path.join(basePath, file.toString());
    
    // Skip directories and non-files
    try {
      if (fs.statSync(filePath).isDirectory()) continue;
    } catch { continue; }
    
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    let fileThreats = [];
    
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      
      if (basename === 'SKILL.md' || basename === 'README.md') {
        const skillResult = scanSkillMd(content, file.toString());
        fileThreats = skillResult.threats;
        results.allowedTools = skillResult.allowedTools;
        results.frontmatter = skillResult.frontmatter;
      } else if (ext === '.py') {
        fileThreats = scanPythonFile(content, file.toString());
      } else if (ext === '.sh' || ext === '.bash') {
        fileThreats = scanBashFile(content, file.toString());
      } else if (ext === '.md') {
        // Scan other markdown files for prompt injection
        const skillResult = scanSkillMd(content, file.toString());
        fileThreats = skillResult.threats;
      }
      
      results.summary.totalFiles++;
      results.files.push({
        path: file.toString(),
        threats: fileThreats.length,
      });
      
      results.threats.push(...fileThreats);
    } catch (err) {
      // Skip binary or unreadable files
      if (err.code !== 'ERR_INVALID_ARG_VALUE') {
        console.error(`Warning: Could not read ${filePath}: ${err.message}`);
      }
    }
  }
  
  // Calculate summary
  results.summary.totalThreats = results.threats.length;
  for (const threat of results.threats) {
    results.summary.bySeverity[threat.severity] = 
      (results.summary.bySeverity[threat.severity] || 0) + 1;
    results.summary.byCategory[threat.category] = 
      (results.summary.byCategory[threat.category] || 0) + 1;
  }
  
  results.clean = results.threats.length === 0;
  results.riskScore = calculateRiskScore(results.threats);
  
  return results;
}

module.exports = {
  scanSkillMd,
  scanPythonFile,
  scanBashFile,
  scanSkillDirectory,
  parseFrontmatter,
};

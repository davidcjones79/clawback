/**
 * Clawback Utilities
 * Shared helper functions
 */

/**
 * Calculate a risk score from 0-100 based on threat severity
 * @param {Array} threats - Array of threat objects
 * @returns {number} Risk score 0-100
 */
function calculateRiskScore(threats) {
  if (!threats || threats.length === 0) return 0;
  
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
 * Get line number from character index in content
 * @param {string} content - The content string
 * @param {number} index - Character index
 * @returns {number} Line number (1-indexed)
 */
function getLineNumber(content, index) {
  if (!content || index === undefined) return 1;
  return content.slice(0, index).split('\n').length;
}

/**
 * Simple YAML parser for OpenClaw configs
 * Handles the common config patterns without requiring js-yaml dependency
 * @param {string} yamlContent - YAML content to parse
 * @returns {object} Parsed config object
 */
function parseSimpleYaml(yamlContent) {
  const result = {};
  const lines = yamlContent.split('\n');
  const stack = [{ obj: result, indent: -1 }];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Skip empty lines and comments
    if (!line.trim() || line.trim().startsWith('#')) continue;
    
    // Calculate indentation
    const indent = line.search(/\S/);
    const content = line.trim();
    
    // Skip if no content
    if (!content) continue;
    
    // Pop stack to find parent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    const parent = stack[stack.length - 1].obj;
    
    // Parse key: value
    const colonIdx = content.indexOf(':');
    if (colonIdx === -1) continue;
    
    const key = content.slice(0, colonIdx).trim();
    let value = content.slice(colonIdx + 1).trim();
    
    // Handle different value types
    if (value === '' || value === '|' || value === '>') {
      // Nested object or multiline - create object
      parent[key] = {};
      stack.push({ obj: parent[key], indent });
    } else if (value.startsWith('[') && value.endsWith(']')) {
      // Inline array
      parent[key] = value.slice(1, -1).split(',').map(s => {
        s = s.trim();
        // Remove quotes
        if ((s.startsWith('"') && s.endsWith('"')) ||
            (s.startsWith("'") && s.endsWith("'"))) {
          s = s.slice(1, -1);
        }
        return s;
      }).filter(s => s);
    } else if (value === 'true') {
      parent[key] = true;
    } else if (value === 'false') {
      parent[key] = false;
    } else if (value === 'null' || value === '~') {
      parent[key] = null;
    } else if (/^-?\d+$/.test(value)) {
      parent[key] = parseInt(value, 10);
    } else if (/^-?\d+\.\d+$/.test(value)) {
      parent[key] = parseFloat(value);
    } else {
      // String - remove quotes if present
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      parent[key] = value;
    }
  }
  
  return result;
}

module.exports = {
  calculateRiskScore,
  getLineNumber,
  parseSimpleYaml,
};

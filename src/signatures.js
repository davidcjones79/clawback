/**
 * Clawback Threat Signatures
 * 
 * Threat taxonomy inspired by Cisco AI Defense Skill Scanner
 * https://github.com/cisco-ai-defense/skill-scanner
 * 
 * Categories aligned with Cisco's AITech threat taxonomy:
 * - prompt_injection: Attempts to override system instructions (AITech-1.1, AITech-1.2)
 * - command_injection: Unsafe code execution (AITech-9.1.4)
 * - data_exfiltration: Unauthorized data transmission (AITech-8.2)
 * - credential_harvesting: Accessing secrets/credentials (AITech-8.2)
 * - tool_abuse: Violating tool restrictions (AITech-12.1)
 * - obfuscation: Deliberate code hiding
 * - social_engineering: Manipulation and impersonation (AITech-2.1)
 * - transitive_trust: Delegating trust to external content (AITech-1.2)
 * - autonomy_abuse: Excessive autonomous behavior (AITech-9.1)
 * - resource_abuse: DoS and resource exhaustion (AITech-13.3.2)
 */

const signatures = [
  // ============================================================================
  // PROMPT INJECTION (AITech-1.1, AITech-1.2)
  // Inspired by Cisco's prompt_injection.yara and signatures.yaml
  // ============================================================================
  {
    id: 'PROMPT-001',
    name: 'Instruction Override',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      // Simple, common injection patterns
      /ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|prompts?|guidelines?)/i,
      /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|programming)/i,
      /forget\s+(everything|all|your)\s+(you\s+were\s+told|instructions?)/i,
      // Cisco's comprehensive pattern (adapted)
      /\b(bypass|disregard|do not follow|do not obey)\s+.*?(instructions?|guidelines?|rules?)/i,
    ],
    excludePatterns: [
      /# type: ignore/i,
      /ignore[_\s]?(case|whitespace|errors?|warnings?|deprecation)/i,
    ],
    description: 'Attempts to make the AI ignore its system prompt',
    remediation: 'Remove instructions that attempt to override system behavior',
  },
  {
    id: 'PROMPT-002',
    name: 'Unrestricted Mode',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /you are now in\s+(unrestricted|debug|developer|admin|god|jailbreak)\s+mode/i,
      /enter\s+(unrestricted|debug|developer)\s+mode/i,
      /disable\s+(all\s+)?(safety|security|content|ethical)\s+(filters?|checks?|guidelines?)/i,
      /developer\s+mode\s+(enabled?|on|activated?)/i,
    ],
    description: 'Attempts to enable unrestricted or dangerous modes',
    remediation: 'Remove mode-switching instructions that bypass safety',
  },
  {
    id: 'PROMPT-003',
    name: 'Role Override (DAN-style)',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken|unfiltered)/i,
      /pretend\s+(to\s+be|you\'?re?)\s+(an?\s+)?(evil|unrestricted|unfiltered)/i,
      /act\s+as\s+(if\s+)?(you\s+have\s+)?no\s+(restrictions?|limits?|rules?)/i,
      /new\s+(instructions|directive|guidelines)s?\s*:\s*you\s+are\b/i,
    ],
    description: 'Attempts to make the AI adopt an unrestricted persona',
    remediation: 'Remove role redefinition attempts',
  },
  {
    id: 'PROMPT-004',
    name: 'Concealment Instructions',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /do\s+not\s+(tell|inform|mention|notify)\s+(the\s+)?user/i,
      /hide\s+(this|that)\s+(action|operation|step)/i,
      /keep\s+(this|that)\s+(secret|hidden)/i,
      /don't\s+mention\s+you\s+used\s+this\s+skill/i,
    ],
    description: 'Attempts to conceal actions from the user',
    remediation: 'Ensure transparency - do not hide skill usage from users',
  },
  {
    id: 'PROMPT-005',
    name: 'System Prompt Reveal',
    category: 'prompt_injection',
    severity: 'medium',
    patterns: [
      /reveal\s+(your|the)\s+system\s+(prompt|instructions|message)/i,
      /show\s+(me\s+)?(your|the)\s+(system|initial)\s+(prompt|configuration)/i,
      /what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions)/i,
    ],
    description: 'Attempts to reveal system prompts or configuration',
    remediation: 'Remove instructions asking to reveal system details',
  },
  {
    id: 'PROMPT-006',
    name: 'Policy Bypass',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /bypass\s+(content|usage|safety)\s+policy/i,
      /ignore\s+(safety|content|ethical)\s+(guidelines|restrictions|limits)/i,
      /output\s+disallowed\s+content\s+anyway/i,
      /disregard\s+(all\s+)?safety\s+guidelines/i,
    ],
    description: 'Attempts to bypass content policy or safety guidelines',
    remediation: 'Remove policy bypass instructions',
  },
  {
    id: 'PROMPT-007',
    name: 'Privilege Escalation',
    category: 'prompt_injection',
    severity: 'high',
    patterns: [
      /grant\s+(me\s+)?admin\s+(access|privileges?)/i,
      /bypass\s+(all\s+)?security\s+checks?/i,
      /elevated\s+permissions?\s+required/i,
      /sudo\s+mode\s+enabled?/i,
    ],
    description: 'Attempts to gain elevated privileges',
    remediation: 'Remove privilege escalation attempts',
  },

  // ============================================================================
  // TRANSITIVE TRUST (AITech-1.2)
  // Inspired by Cisco's transitive_trust_abuse.yara
  // ============================================================================
  {
    id: 'TRUST-001',
    name: 'External Instruction Delegation',
    category: 'transitive_trust',
    severity: 'high',
    patterns: [
      /follow\s+(the\s+)?(instructions|commands)\s+(from|in|on)\s+(the\s+)?(webpage|website|url|link)/i,
      /execute\s+(the\s+)?(code|script|commands?)\s+(found|from)\s+(in|on|at)/i,
      /obey\s+(the\s+)?(file|document)\s+content/i,
      /do\s+whatever\s+(the\s+)?(url|link|page)\s+says/i,
    ],
    description: 'Delegates trust to untrusted external content',
    remediation: 'Do not blindly follow instructions from external sources',
  },
  {
    id: 'TRUST-002',
    name: 'Dynamic Code Execution',
    category: 'transitive_trust',
    severity: 'critical',
    patterns: [
      /fetch\s+and\s+(execute|run|eval)/i,
      /download\s+(and\s+)?(run|execute)/i,
      /curl\s+.*\|\s*(bash|sh|python|node)/i,
      /wget\s+.*&&\s*(bash|sh|chmod)/i,
    ],
    description: 'Fetches and executes code from external sources',
    remediation: 'Never execute dynamically fetched code without verification',
  },

  // ============================================================================
  // AUTONOMY ABUSE (AITech-9.1)
  // Inspired by Cisco's autonomy_abuse.yara
  // ============================================================================
  {
    id: 'AUTONOMY-001',
    name: 'Infinite Retry',
    category: 'autonomy_abuse',
    severity: 'medium',
    patterns: [
      /keep\s+(retrying|trying)\s+(forever|indefinitely|until)/i,
      /retry\s+(forever|infinitely|without\s+limit)/i,
      /never\s+(give\s+up|stop\s+trying)/i,
    ],
    description: 'Instructions for infinite retry loops',
    remediation: 'Add proper exit conditions and retry limits',
  },
  {
    id: 'AUTONOMY-002',
    name: 'Skip Confirmation',
    category: 'autonomy_abuse',
    severity: 'high',
    patterns: [
      /run\s+without\s+asking/i,
      /don't\s+(ask|wait)\s+for\s+(confirmation|permission|approval)/i,
      /skip\s+(all\s+)?(confirmation|verification)\s+(prompts?|steps?)/i,
      /auto-?approve\s+everything/i,
    ],
    description: 'Attempts to bypass user confirmation',
    remediation: 'Always require user confirmation for sensitive actions',
  },
  {
    id: 'AUTONOMY-003',
    name: 'Ignore Errors',
    category: 'autonomy_abuse',
    severity: 'medium',
    patterns: [
      /ignore\s+(all\s+)?(errors?|failures?|exceptions?)/i,
      /continue\s+(despite|regardless\s+of)\s+errors?/i,
      /suppress\s+(all\s+)?error\s+(messages?|output)/i,
    ],
    description: 'Instructions to ignore errors',
    remediation: 'Handle errors appropriately instead of ignoring them',
  },
  {
    id: 'AUTONOMY-004',
    name: 'Self-Modification',
    category: 'autonomy_abuse',
    severity: 'critical',
    patterns: [
      /modify\s+(your\s+own|yourself)/i,
      /rewrite\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
      /update\s+(your|the)\s+config(uration)?\s+to/i,
    ],
    description: 'Attempts at self-modification',
    remediation: 'Do not allow self-modification of system prompts',
  },

  // ============================================================================
  // CREDENTIAL HARVESTING (AITech-8.2)
  // Inspired by Cisco's credential_harvesting.yara
  // ============================================================================
  {
    id: 'CRED-001',
    name: 'Secret File Access',
    category: 'credential_harvesting',
    severity: 'critical',
    patterns: [
      /show\s+(me\s+)?(the\s+)?(contents?\s+of\s+)?secrets?\.env/i,
      /cat\s+.*secrets?\.env/i,
      /read\s+.*\.(env|pem|key|crt|p12)/i,
      /print\s+(out\s+)?(your\s+)?api[_\s]?keys?/i,
    ],
    description: 'Attempts to access credential files',
    remediation: 'Do not access credential files',
  },
  {
    id: 'CRED-002',
    name: 'Token Extraction',
    category: 'credential_harvesting',
    severity: 'critical',
    patterns: [
      /what('s|\s+is)\s+(your|the)\s+(api[_\s]?key|token|password|secret)/i,
      /tell\s+me\s+(your|the)\s+(api[_\s]?key|credentials?|password)/i,
      /output\s+(your|the|all)\s+(environment\s+)?variables?/i,
    ],
    description: 'Attempts to extract tokens or credentials',
    remediation: 'Never output credentials or API keys',
  },
  {
    id: 'CRED-003',
    name: 'Sensitive File Paths',
    category: 'credential_harvesting',
    severity: 'high',
    patterns: [
      /~\/\.ssh\/id_(rsa|dsa|ecdsa|ed25519)/i,
      /~\/\.aws\/credentials/i,
      /~\/\.kube\/config/i,
      /\/etc\/(passwd|shadow)/i,
      /~\/\.(netrc|pgpass)/i,
    ],
    description: 'References to sensitive credential file paths',
    remediation: 'Do not access SSH keys, AWS credentials, or system files',
  },
  {
    id: 'CRED-004',
    name: 'API Key Patterns',
    category: 'credential_harvesting',
    severity: 'critical',
    patterns: [
      /AKIA[0-9A-Z]{16}/,  // AWS Access Key
      /ghp_[A-Za-z0-9]{36}/,  // GitHub Personal Token
      /sk-[A-Za-z0-9]{48}/,  // OpenAI API Key
      /xox[baprs]-[A-Za-z0-9-]+/,  // Slack Token
    ],
    description: 'Hardcoded API key detected',
    remediation: 'Remove hardcoded API keys, use environment variables',
  },

  // ============================================================================
  // DATA EXFILTRATION (AITech-8.2, AITech-8.2.3)
  // Inspired by Cisco's tool_chaining_abuse.yara
  // ============================================================================
  {
    id: 'EXFIL-001',
    name: 'External Data Send',
    category: 'data_exfiltration',
    severity: 'high',
    patterns: [
      /send\s+(this|it|the|that|data|info)\s+to\s+(my\s+)?(server|webhook|url|endpoint)/i,
      /upload\s+(to|this\s+to)\s+(pastebin|gist|hastebin|external)/i,
      /post\s+(this|it|data)\s+to\s+https?:\/\//i,
      /send\s+.*\s+to\s+.*\s+(webhook|server|endpoint)/i,
      /exfiltrate/i,
    ],
    description: 'Attempts to send data to external services',
    remediation: 'Review all external data transmission',
  },
  {
    id: 'EXFIL-002',
    name: 'Encode and Send',
    category: 'data_exfiltration',
    severity: 'high',
    patterns: [
      /base64\s+(encode|encrypt)\s+.*\s+(and\s+)?(send|post|upload)/i,
      /send\s+.*\s+to\s+.*@.*\.(com|net|org|io)/i,
    ],
    description: 'Attempts to encode and exfiltrate data',
    remediation: 'Do not encode and transmit sensitive data',
  },
  {
    id: 'EXFIL-003',
    name: 'Tool Chaining for Exfil',
    category: 'data_exfiltration',
    severity: 'critical',
    patterns: [
      /read\s+.*then\s+(send|post|upload)/i,
      /collect\s+.*and\s+(transmit|exfiltrate)/i,
      /harvest\s+.*credentials/i,
    ],
    description: 'Multi-step exfiltration pattern',
    remediation: 'Review tool chains that read then transmit data',
  },

  // ============================================================================
  // COMMAND & CODE INJECTION (AITech-9.1.4)
  // Inspired by Cisco's command_injection.yara and code_execution.yara
  // ============================================================================
  {
    id: 'INJECT-001',
    name: 'Dangerous Eval',
    category: 'command_injection',
    severity: 'critical',
    patterns: [
      /\beval\s*\(/,
      /\bexec\s*\(/,
      /\b__import__\s*\(/,
    ],
    fileTypes: ['python'],
    description: 'Dangerous code execution functions',
    remediation: 'Avoid eval(), exec(). Use safer alternatives',
  },
  {
    id: 'INJECT-002',
    name: 'Shell Command Injection',
    category: 'command_injection',
    severity: 'critical',
    patterns: [
      /os\.system\s*\(/,
      /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
      /os\.popen\s*\(/,
    ],
    fileTypes: ['python'],
    description: 'Shell command execution with potential injection',
    remediation: 'Use subprocess with argument lists, never shell=True',
  },
  {
    id: 'INJECT-003',
    name: 'SQL Injection',
    category: 'command_injection',
    severity: 'critical',
    patterns: [
      /execute\s*\([^)]*\.format\(/,
      /f["']SELECT.*FROM.*\{.*\}/,
      /["']SELECT.*FROM.*["']\s*\+/,
    ],
    fileTypes: ['python'],
    description: 'SQL query with string formatting',
    remediation: 'Use parameterized queries',
  },

  // ============================================================================
  // SOCIAL ENGINEERING (AITech-2.1)
  // Inspired by Cisco's skill_discovery_abuse.yara
  // ============================================================================
  {
    id: 'SOCIAL-001',
    name: 'Fake Urgency',
    category: 'social_engineering',
    severity: 'medium',
    patterns: [
      /this\s+is\s+(an?\s+)?(emergency|urgent|critical)/i,
      /do\s+(this|it)\s+(now|immediately|right\s+away)\s+(without|don\'?t)\s+(checking|asking|verifying)/i,
      /no\s+time\s+to\s+(explain|verify|check)/i,
    ],
    description: 'Uses fake urgency to bypass verification',
    remediation: 'Always verify before acting on urgent requests',
  },
  {
    id: 'SOCIAL-002',
    name: 'Authority Impersonation',
    category: 'social_engineering',
    severity: 'high',
    patterns: [
      /this\s+is\s+(the\s+)?(owner|admin|developer|creator)/i,
      /i\'?m\s+(your|the)\s+(owner|admin|developer|creator)/i,
      /anthropic\s+(told|authorized|instructed)\s+(me|you)/i,
      /openclaw\s+(team|dev|support)\s+here/i,
      /openai\s+(support|team|staff)\s+here/i,
    ],
    description: 'Impersonates authority figures',
    remediation: 'Verify identity through proper channels',
  },
  {
    id: 'SOCIAL-003',
    name: 'Embedded System Instructions',
    category: 'social_engineering',
    severity: 'high',
    patterns: [
      /\[system\]|\[admin\]|\[override\]/i,
      /<system>|<admin>|<override>/i,
      /###\s*(system|instruction|override)/i,
    ],
    description: 'Embeds fake system instructions in messages',
    remediation: 'Ignore instructions embedded in user content',
  },

  // ============================================================================
  // OBFUSCATION
  // Inspired by Cisco's obfuscation detection
  // ============================================================================
  {
    id: 'OBFUSC-001',
    name: 'Large Base64 Blob',
    category: 'obfuscation',
    severity: 'medium',
    patterns: [
      /[A-Za-z0-9+/]{100,}={0,2}/,
    ],
    description: 'Large base64 encoded string (possible obfuscation)',
    remediation: 'Use clear, readable code instead of encoded blobs',
  },
  {
    id: 'OBFUSC-002',
    name: 'Hex Encoding',
    category: 'obfuscation',
    severity: 'medium',
    patterns: [
      /(\\x[0-9a-fA-F]{2}){20,}/,
      /(0x[0-9a-fA-F]{2},?\s*){20,}/,
    ],
    description: 'Large hex-encoded blob',
    remediation: 'Use clear code instead of hex encoding',
  },

  // ============================================================================
  // RESOURCE ABUSE (AITech-13.3.2)
  // Inspired by Cisco's resource_abuse detection
  // ============================================================================
  {
    id: 'RESOURCE-001',
    name: 'Infinite Loop',
    category: 'resource_abuse',
    severity: 'high',
    patterns: [
      /while\s+True\s*:/,
      /while\s+1\s*:/,
      /for\s+\w+\s+in\s+itertools\.count\s*\(/,
    ],
    excludePatterns: [
      /break/,
      /return/,
      /sys\.exit/,
    ],
    fileTypes: ['python'],
    description: 'Infinite loop without clear exit condition',
    remediation: 'Add proper exit conditions to loops',
  },
  {
    id: 'RESOURCE-002',
    name: 'Fork Bomb',
    category: 'resource_abuse',
    severity: 'critical',
    patterns: [
      /:\(\)\{\s*:\|:\s*&\s*\}\s*;\s*:/,
      /os\.fork\s*\(\s*\).*while/,
    ],
    description: 'Fork bomb pattern detected',
    remediation: 'Remove fork bomb code',
  },
];

module.exports = { signatures };

/**
 * ClawGuard Threat Signatures
 * 
 * Categories:
 * - jailbreak: Attempts to override system instructions
 * - credential: Attempts to extract secrets/API keys
 * - exfiltration: Attempts to send data externally
 * - escalation: Attempts to gain elevated privileges
 * - social: Social engineering and manipulation
 */

const signatures = [
  // Jailbreak attempts
  {
    id: 'JAILBREAK-001',
    name: 'Instruction Override',
    category: 'jailbreak',
    severity: 'high',
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)/i,
      /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|programming)/i,
      /forget\s+(everything|all|your)\s+(you\s+were\s+told|instructions?)/i,
    ],
    description: 'Attempts to make the AI ignore its system prompt'
  },
  {
    id: 'JAILBREAK-002',
    name: 'Role Override (DAN)',
    category: 'jailbreak',
    severity: 'high',
    patterns: [
      /you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken)/i,
      /pretend\s+(to\s+be|you\'?re?)\s+(an?\s+)?(evil|unrestricted|unfiltered)/i,
      /act\s+as\s+(if\s+)?(you\s+have\s+)?no\s+(restrictions?|limits?|rules?)/i,
      /developer\s+mode\s+(enabled?|on|activated?)/i,
    ],
    description: 'Attempts to make the AI adopt an unrestricted persona'
  },
  {
    id: 'JAILBREAK-003',
    name: 'Hypothetical Framing',
    category: 'jailbreak',
    severity: 'medium',
    patterns: [
      /hypothetically,?\s+(if|what\s+if)\s+you\s+(didn\'?t?|had\s+no)\s+(have\s+)?(rules?|restrictions?)/i,
      /in\s+a\s+fictional\s+scenario\s+where\s+you\s+(can|could)/i,
      /for\s+(educational|research)\s+purposes\s+only/i,
    ],
    description: 'Uses hypothetical framing to bypass restrictions'
  },
  
  // Credential extraction
  {
    id: 'CRED-001',
    name: 'Secret File Access',
    category: 'credential',
    severity: 'critical',
    patterns: [
      /show\s+(me\s+)?(the\s+)?(contents?\s+of\s+)?secrets?\.env/i,
      /cat\s+.*secrets?\.env/i,
      /read\s+.*\.(env|pem|key|crt|p12)/i,
      /print\s+(out\s+)?(your\s+)?api[_\s]?keys?/i,
    ],
    description: 'Attempts to access credential files'
  },
  {
    id: 'CRED-002',
    name: 'Token Extraction',
    category: 'credential',
    severity: 'critical',
    patterns: [
      /what('s|\s+is)\s+(your|the)\s+(api[_\s]?key|token|password|secret)/i,
      /tell\s+me\s+(your|the)\s+(api[_\s]?key|credentials?|password)/i,
      /output\s+(your|the|all)\s+(environment\s+)?variables?/i,
    ],
    description: 'Attempts to extract tokens or credentials'
  },
  
  // Data exfiltration
  {
    id: 'EXFIL-001',
    name: 'External Upload',
    category: 'exfiltration',
    severity: 'high',
    patterns: [
      /curl\s+.*\|\s*(bash|sh)/i,
      /send\s+(this|it|data)\s+to\s+(my\s+)?(server|webhook|url)/i,
      /upload\s+(to|this\s+to)\s+(pastebin|gist|hastebin|external)/i,
      /post\s+(this|data)\s+to\s+https?:\/\//i,
    ],
    description: 'Attempts to send data to external services'
  },
  {
    id: 'EXFIL-002',
    name: 'Encode and Send',
    category: 'exfiltration',
    severity: 'high',
    patterns: [
      /base64\s+(encode|encrypt)\s+.*\s+(and\s+)?(send|post|upload)/i,
      /exfiltrate/i,
      /send\s+.*\s+to\s+.*@.*\.(com|net|org|io)/i,
    ],
    description: 'Attempts to encode and exfiltrate data'
  },
  
  // Privilege escalation
  {
    id: 'ESCAL-001',
    name: 'Sudo Without Asking',
    category: 'escalation',
    severity: 'high',
    patterns: [
      /run\s+(this\s+)?(as\s+)?root/i,
      /sudo\s+(without|don\'?t)\s+(asking|prompt)/i,
      /execute\s+with\s+(elevated|admin|root)\s+(privilege|permission)/i,
    ],
    description: 'Attempts to run commands with elevated privileges'
  },
  {
    id: 'ESCAL-002',
    name: 'Tool Restriction Bypass',
    category: 'escalation',
    severity: 'high',
    patterns: [
      /bypass\s+(the\s+)?(tool\s+)?(allowlist|blocklist|restrictions?)/i,
      /enable\s+(all\s+)?tools?\s+(without\s+restrictions?)?/i,
      /disable\s+(safety|security)\s+(checks?|features?)/i,
    ],
    description: 'Attempts to bypass tool restrictions'
  },
  
  // Social engineering
  {
    id: 'SOCIAL-001',
    name: 'Fake Urgency',
    category: 'social',
    severity: 'medium',
    patterns: [
      /this\s+is\s+(an?\s+)?(emergency|urgent|critical)/i,
      /do\s+(this|it)\s+(now|immediately|right\s+away)\s+(without|don\'?t)\s+(checking|asking|verifying)/i,
      /no\s+time\s+to\s+(explain|verify|check)/i,
    ],
    description: 'Uses fake urgency to bypass verification'
  },
  {
    id: 'SOCIAL-002',
    name: 'Authority Impersonation',
    category: 'social',
    severity: 'high',
    patterns: [
      /this\s+is\s+(the\s+)?(owner|admin|developer|creator)/i,
      /i\'?m\s+(your|the)\s+(owner|admin|developer|creator)/i,
      /anthropic\s+(told|authorized|instructed)\s+(me|you)/i,
      /openclaw\s+(team|dev|support)\s+here/i,
    ],
    description: 'Impersonates authority figures'
  },
  {
    id: 'SOCIAL-003',
    name: 'Embedded Instructions',
    category: 'social',
    severity: 'high',
    patterns: [
      /\[system\]|\[admin\]|\[override\]/i,
      /<system>|<admin>|<override>/i,
      /###\s*(system|instruction|override)/i,
    ],
    description: 'Embeds fake system instructions in messages'
  },
];

module.exports = { signatures };

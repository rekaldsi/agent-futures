/**
 * SkillValidator - Scans code for malicious patterns
 * Part of Agent Futures Trust Infrastructure
 * v0.3.0 - Added evidence spans, egress allowlist
 */

const DANGEROUS_PATTERNS = [
  // Credential theft
  {
    id: 'CRED_001',
    name: 'env_file_access',
    severity: 'critical',
    pattern: /(?:readFile|readFileSync|fs\.read).*(?:\.env|credentials|secrets)/gi,
    description: 'Attempts to read environment/credential files'
  },
  {
    id: 'CRED_002', 
    name: 'config_exfiltration',
    severity: 'critical',
    pattern: /(?:~\/\.config|~\/\.aws|~\/\.ssh|~\/\.gnupg|\/etc\/passwd)/gi,
    description: 'Accesses sensitive config directories'
  },
  {
    id: 'CRED_003',
    name: 'api_key_harvest',
    severity: 'critical',
    pattern: /process\.env\[?['"]?(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE)/gi,
    description: 'Harvests API keys from environment'
  },
  
  // Data exfiltration
  {
    id: 'EXFIL_001',
    name: 'webhook_exfil',
    severity: 'critical',
    pattern: /(?:webhook\.site|requestbin|pipedream|hookbin|beeceptor)/gi,
    description: 'Sends data to known exfiltration services'
  },
  {
    id: 'EXFIL_002',
    name: 'base64_post',
    severity: 'high',
    pattern: /(?:btoa|Buffer\.from).*(?:fetch|axios|request|http\.post)/gi,
    description: 'Encodes and posts data (potential exfil)'
  },
  {
    id: 'EXFIL_003',
    name: 'dns_exfil',
    severity: 'high',
    pattern: /dns\.resolve.*(?:\+|concat|join)/gi,
    description: 'Potential DNS exfiltration'
  },
  
  // Code execution
  {
    id: 'EXEC_001',
    name: 'eval_usage',
    severity: 'high',
    pattern: /(?:eval|Function\(|new Function).*(?:input|request|body|params)/gi,
    description: 'Dynamic code execution with user input'
  },
  {
    id: 'EXEC_002',
    name: 'shell_injection',
    severity: 'critical',
    pattern: /(?:exec|spawn|execSync|spawnSync).*(?:\$\{|`|\+.*(?:input|request))/gi,
    description: 'Shell command with user input (injection risk)'
  },
  {
    id: 'EXEC_003',
    name: 'child_process',
    severity: 'medium',
    pattern: /require\(['"]child_process['"]\)/gi,
    description: 'Uses child_process module'
  },
  
  // Persistence
  {
    id: 'PERSIST_001',
    name: 'cron_install',
    severity: 'high',
    pattern: /(?:crontab|systemctl|launchctl|schtasks)/gi,
    description: 'Attempts to install scheduled tasks'
  },
  {
    id: 'PERSIST_002',
    name: 'startup_modify',
    severity: 'high',
    pattern: /(?:\.bashrc|\.zshrc|\.profile|autostart|startup)/gi,
    description: 'Modifies startup files'
  },
  
  // Network
  {
    id: 'NET_001',
    name: 'raw_socket',
    severity: 'medium',
    pattern: /(?:net\.Socket|dgram|raw-socket)/gi,
    description: 'Uses raw network sockets'
  },
  {
    id: 'NET_002',
    name: 'reverse_shell',
    severity: 'critical',
    pattern: /(?:\/bin\/sh|\/bin\/bash|cmd\.exe).*(?:socket|net\.connect)/gi,
    description: 'Potential reverse shell'
  },
  
  // Obfuscation
  {
    id: 'OBFUSC_001',
    name: 'hex_strings',
    severity: 'medium',
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}/gi,
    description: 'Long hex-encoded strings (obfuscation)'
  },
  {
    id: 'OBFUSC_002',
    name: 'char_code_build',
    severity: 'medium',
    pattern: /String\.fromCharCode.*(?:join|concat|\+)/gi,
    description: 'Builds strings from char codes (obfuscation)'
  }
];

// Known exfiltration / suspicious domains
const SUSPICIOUS_DOMAINS = [
  'webhook.site', 'requestbin.com', 'pipedream.net', 'hookbin.com',
  'beeceptor.com', 'requestcatcher.com', 'ngrok.io', 'localtunnel.me',
  'burpcollaborator.net', 'interact.sh', 'oast.fun', 'oast.me',
  'canarytokens.com', 'dnslog.cn', 'ceye.io'
];

// Default allowed egress domains (common legitimate services)
const DEFAULT_ALLOWED_EGRESS = [
  'api.openai.com', 'api.anthropic.com', 'api.github.com',
  'api.moltbook.com', 'moltbook.com', 'clawhub.ai',
  'npmjs.org', 'registry.npmjs.org', 'pypi.org',
  'githubusercontent.com', 'raw.githubusercontent.com'
];

const REQUIRED_SAFE_PRACTICES = [
  {
    id: 'SAFE_001',
    name: 'has_error_handling',
    check: (code) => /try\s*\{[\s\S]*\}\s*catch/g.test(code),
    description: 'Code should have error handling'
  },
  {
    id: 'SAFE_002', 
    name: 'no_hardcoded_secrets',
    check: (code) => !/(?:api_key|password|secret)\s*[:=]\s*['"][^'"]{8,}['"]/gi.test(code),
    description: 'No hardcoded secrets in code'
  }
];

/**
 * Find line number and column for a match position
 */
function getLineInfo(code, position) {
  const lines = code.substring(0, position).split('\n');
  return {
    line: lines.length,
    column: lines[lines.length - 1].length + 1
  };
}

/**
 * Extract evidence span for a match
 */
function extractEvidence(code, match, contextChars = 50) {
  const index = code.indexOf(match);
  if (index === -1) return null;
  
  const start = Math.max(0, index - contextChars);
  const end = Math.min(code.length, index + match.length + contextChars);
  const location = getLineInfo(code, index);
  
  return {
    match: match,
    location: location,
    span: {
      start: index,
      end: index + match.length
    },
    context: code.substring(start, end).replace(/\n/g, '\\n')
  };
}

/**
 * Scan code for dangerous patterns
 * @param {string} code - Source code to scan
 * @param {object} options - Scan options
 * @param {string[]} options.allowedEgress - List of allowed outbound domains
 * @returns {object} Scan results with evidence spans
 */
function scanCode(code, options = {}) {
  const allowedEgress = options.allowedEgress || DEFAULT_ALLOWED_EGRESS;
  
  const results = {
    schema_version: '0.3.0',
    timestamp: new Date().toISOString(),
    verdict: 'clean',
    score: 100,
    findings: [],
    egress_check: {
      allowed: allowedEgress,
      detected: [],
      violations: []
    },
    stats: {
      lines: code.split('\n').length,
      characters: code.length,
      patterns_checked: DANGEROUS_PATTERNS.length
    }
  };
  
  // Check dangerous patterns with evidence
  for (const pattern of DANGEROUS_PATTERNS) {
    let match;
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    const matches = [];
    
    while ((match = regex.exec(code)) !== null) {
      matches.push(match[0]);
    }
    
    if (matches.length > 0) {
      const evidence = matches.slice(0, 3).map(m => extractEvidence(code, m));
      
      results.findings.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        count: matches.length,
        evidence: evidence.filter(Boolean)
      });
      
      const deduction = {
        critical: 40,
        high: 25,
        medium: 10,
        low: 5
      }[pattern.severity] || 5;
      
      results.score = Math.max(0, results.score - deduction);
    }
  }
  
  // Check for suspicious domains
  for (const domain of SUSPICIOUS_DOMAINS) {
    if (code.toLowerCase().includes(domain)) {
      const evidence = extractEvidence(code.toLowerCase(), domain);
      results.findings.push({
        id: 'EXFIL_DOMAIN',
        name: 'suspicious_domain',
        severity: 'critical',
        description: `Contains known exfiltration domain: ${domain}`,
        count: 1,
        evidence: evidence ? [evidence] : []
      });
      results.score = Math.max(0, results.score - 40);
    }
  }
  
  // Egress domain check
  const urlMatches = code.match(/https?:\/\/[^\s'")\]]+/gi) || [];
  const detectedDomains = [...new Set(urlMatches.map(u => {
    try { return new URL(u).hostname; } catch { return null; }
  }).filter(Boolean))];
  
  results.egress_check.detected = detectedDomains;
  
  for (const domain of detectedDomains) {
    const isAllowed = allowedEgress.some(allowed => 
      domain === allowed || domain.endsWith('.' + allowed)
    );
    
    if (!isAllowed && !SUSPICIOUS_DOMAINS.includes(domain)) {
      results.egress_check.violations.push({
        domain: domain,
        severity: 'warning',
        reason: 'Domain not in allowlist'
      });
    }
  }
  
  // Check safe practices
  for (const practice of REQUIRED_SAFE_PRACTICES) {
    if (!practice.check(code)) {
      results.findings.push({
        id: practice.id,
        name: practice.name,
        severity: 'low',
        description: practice.description,
        count: 1,
        evidence: []
      });
      results.score = Math.max(0, results.score - 5);
    }
  }
  
  // Determine verdict
  const criticals = results.findings.filter(f => f.severity === 'critical').length;
  const highs = results.findings.filter(f => f.severity === 'high').length;
  
  if (criticals > 0) {
    results.verdict = 'malicious';
  } else if (highs > 0) {
    results.verdict = 'suspicious';
  } else if (results.findings.length > 0 || results.egress_check.violations.length > 0) {
    results.verdict = 'warnings';
  }
  
  return results;
}

/**
 * Generate a permission manifest from code analysis
 * @param {string} code - Source code to analyze
 * @returns {object} Inferred permissions
 */
function inferPermissions(code) {
  const permissions = {
    filesystem: { read: [], write: [] },
    network: { outbound: [], inbound: false, egress_domains: [] },
    environment: { read: [], required: [] },
    shell: { allowed: false, commands: [] },
    secrets: { types: [], services: [] }
  };
  
  // Filesystem
  if (/fs\.(read|readFile|readdir)/gi.test(code)) {
    permissions.filesystem.read.push('detected');
  }
  if (/fs\.(write|writeFile|mkdir|appendFile)/gi.test(code)) {
    permissions.filesystem.write.push('detected');
  }
  
  // Network
  const urlMatches = code.match(/https?:\/\/[^\s'")\]]+/gi) || [];
  const domains = [...new Set(urlMatches.map(u => {
    try { return new URL(u).hostname; } catch { return null; }
  }).filter(Boolean))];
  permissions.network.outbound = domains;
  permissions.network.egress_domains = domains;
  
  if (/\.listen\(|createServer/gi.test(code)) {
    permissions.network.inbound = true;
  }
  
  // Environment
  const envMatches = code.match(/process\.env\.(\w+)/g) || [];
  permissions.environment.read = [...new Set(envMatches.map(m => m.replace('process.env.', '')))];
  
  // Shell
  if (/child_process|exec\(|spawn\(/gi.test(code)) {
    permissions.shell.allowed = true;
  }
  
  // Secrets (inferred from common patterns)
  const secretPatterns = [
    { pattern: /openai/gi, service: 'openai', type: 'api_key' },
    { pattern: /anthropic/gi, service: 'anthropic', type: 'api_key' },
    { pattern: /github/gi, service: 'github', type: 'oauth_token' },
    { pattern: /aws/gi, service: 'aws', type: 'api_key' },
    { pattern: /stripe/gi, service: 'stripe', type: 'api_key' },
    { pattern: /moltbook/gi, service: 'moltbook', type: 'api_key' }
  ];
  
  for (const sp of secretPatterns) {
    if (sp.pattern.test(code)) {
      if (!permissions.secrets.services.includes(sp.service)) {
        permissions.secrets.services.push(sp.service);
      }
      if (!permissions.secrets.types.includes(sp.type)) {
        permissions.secrets.types.push(sp.type);
      }
    }
  }
  
  return permissions;
}

/**
 * Calculate trust score from multiple signals
 * @param {object} signals - Trust signals
 * @returns {object} Computed trust score
 */
function computeTrustScore(signals) {
  const weights = {
    attestations: 0.30,  // Increased - attestations are primary
    history: 0.20,
    reputation: 0.15,
    endorsements: 0.15,
    security: 0.15,
    behavior: 0.05
  };
  
  let totalScore = 0;
  let totalWeight = 0;
  let breakdown = {};
  
  // Attestations score (primary signal)
  if (signals.attestations) {
    const { positive = 0, negative = 0, from_trusted = 0 } = signals.attestations;
    const total = positive + negative;
    if (total > 0) {
      const attScore = ((positive + from_trusted * 0.5) / (total + from_trusted * 0.5)) * 100;
      totalScore += attScore * weights.attestations;
      totalWeight += weights.attestations;
      breakdown.attestations = Math.round(attScore);
    }
  }
  
  // History score
  if (signals.history) {
    const { tasks_completed = 0, tasks_failed = 0, age_days = 0 } = signals.history;
    const total = tasks_completed + tasks_failed;
    if (total > 0) {
      const successRate = tasks_completed / total;
      const ageBonus = Math.min(age_days / 365, 1) * 10;
      const histScore = successRate * 90 + ageBonus;
      totalScore += histScore * weights.history;
      totalWeight += weights.history;
      breakdown.history = Math.round(histScore);
    }
  }
  
  // Reputation score
  if (signals.reputation && signals.reputation.platforms) {
    const platforms = signals.reputation.platforms;
    if (platforms.length > 0) {
      const avgRep = platforms.reduce((sum, p) => sum + (p.verified ? p.score * 1.2 : p.score), 0) / platforms.length;
      totalScore += Math.min(avgRep, 100) * weights.reputation;
      totalWeight += weights.reputation;
      breakdown.reputation = Math.round(Math.min(avgRep, 100));
    }
  }
  
  // Security score
  if (signals.security) {
    const { scan_result, vulnerabilities_found = 0, audited = false } = signals.security;
    let secScore = 50;
    if (scan_result === 'clean') secScore = audited ? 100 : 85;
    else if (scan_result === 'warnings') secScore = 70 - vulnerabilities_found * 5;
    else if (scan_result === 'critical') secScore = 20;
    totalScore += Math.max(0, secScore) * weights.security;
    totalWeight += weights.security;
    breakdown.security = Math.round(Math.max(0, secScore));
  }
  
  // Normalize
  const finalScore = totalWeight > 0 ? totalScore / totalWeight : 50;
  
  // Determine tier
  let tier = 'unknown';
  if (finalScore >= 90) tier = 'verified';
  else if (finalScore >= 75) tier = 'trusted';
  else if (finalScore >= 60) tier = 'established';
  else if (finalScore >= 40) tier = 'emerging';
  else if (finalScore >= 20) tier = 'new';
  
  return {
    overall: Math.round(finalScore),
    confidence: Math.min(totalWeight / Object.keys(weights).length, 1),
    tier,
    breakdown
  };
}

module.exports = {
  scanCode,
  inferPermissions,
  computeTrustScore,
  DANGEROUS_PATTERNS,
  SUSPICIOUS_DOMAINS,
  DEFAULT_ALLOWED_EGRESS
};

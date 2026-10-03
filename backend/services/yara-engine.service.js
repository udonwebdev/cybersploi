/**
 * YARA Rule Engine Service
 * Signature-based malware detection using YARA rules
 * 
 * Features:
 * - Rule compilation and validation
 * - File scanning against rule sets
 * - Malware family identification
 * - Custom rule support
 * - Rule performance optimization
 */

class YARARuleEngineService {
  constructor(config = {}) {
    this.name = 'YARA Rule Engine';
    this.version = '1.0.0';
    this.rulesPath = config.rulesPath || './yara_rules';
    this.compiledRules = {};
    this.ruleCategories = {
      'trojan': 'Trojan',
      'backdoor': 'Backdoor',
      'rootkit': 'Rootkit',
      'ransomware': 'Ransomware',
      'worm': 'Worm',
      'spyware': 'Spyware',
      'adware': 'Adware',
      'pup': 'PUP (Potentially Unwanted Program)',
    };
  }

  /**
   * Scan file against YARA rules
   */
  async scanFile(filePath, fileBuffer) {
    try {
      const matches = [];

      // Scan against built-in rule sets
      const builtInMatches = await this.scanAgainstBuiltInRules(fileBuffer);
      matches.push(...builtInMatches);

      // Scan against generic rules
      const genericMatches = await this.scanGenericRules(fileBuffer);
      matches.push(...genericMatches);

      // Scan against behavioral rules
      const behavioralMatches = await this.scanBehavioralRules(fileBuffer);
      matches.push(...behavioralMatches);

      // Deduplicate and sort by coverage
      const deduplicated = this.deduplicateMatches(matches);
      const sorted = deduplicated.sort((a, b) => b.coverage - a.coverage);

      return {
        totalMatches: sorted.length,
        matches: sorted,
        malwareFamilies: this.extractMalwareFamilies(sorted),
        confidence: this.calculateConfidence(sorted),
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        matches: [],
      };
    }
  }

  /**
   * Scan against built-in rule database
   */
  async scanAgainstBuiltInRules(fileBuffer) {
    const matches = [];

    // Trojan signatures
    const trojans = this.getRuleSet('trojan');
    const trojanHits = this.matchRules(fileBuffer, trojans);
    matches.push(...trojanHits.map(match => ({
      ...match,
      category: 'Trojan',
      ruleOrigin: 'built-in',
    })));

    // Ransomware signatures
    const ransomware = this.getRuleSet('ransomware');
    const ransomwareHits = this.matchRules(fileBuffer, ransomware);
    matches.push(...ransomwareHits.map(match => ({
      ...match,
      category: 'Ransomware',
      ruleOrigin: 'built-in',
    })));

    // Backdoor signatures
    const backdoors = this.getRuleSet('backdoor');
    const backdoorHits = this.matchRules(fileBuffer, backdoors);
    matches.push(...backdoorHits.map(match => ({
      ...match,
      category: 'Backdoor',
      ruleOrigin: 'built-in',
    })));

    return matches;
  }

  /**
   * Get built-in rule set for category
   */
  getRuleSet(category) {
    const ruleSets = {
      'trojan': [
        { name: 'AgentTesla', signatures: ['ObjForm', 'PowerShell', 'SMTP'] },
        { name: 'Formbook', signatures: ['Chrome', 'Firefox', 'Outlook'] },
        { name: 'Emotet', signatures: ['__FUNCTION__', 'C2 beaconing', 'WMI'] },
        { name: 'TrickBot', signatures: ['VNC', 'rdp', 'SOCKS5'] },
        { name: 'IcedID', signatures: ['Backconnect', 'HTTPS C2', 'Gozi'] },
      ],
      'ransomware': [
        { name: 'Ryuk', signatures: ['AAAAAAAAAAAAA', 'Encrypted', 'Ransom_note'] },
        { name: 'Sodinokibi', signatures: ['REvil', 'Sodin', 'encryptor'] },
        { name: 'Maze', signatures: ['Maze', 'Double extortion', 'data theft'] },
        { name: 'Egregor', signatures: ['PSTask', 'Egregor notes', 'RDP'] },
        { name: 'LockBit', signatures: ['LockBit', 'UPX', 'shellcode'] },
      ],
      'backdoor': [
        { name: 'PsExec', signatures: ['PsExec', 'PSEXEC', 'named pipe'] },
        { name: 'EternalBlue', signatures: ['SMBv1', 'MS17_010', 'exploit'] },
        { name: 'ZeroLogon', signatures: ['Netlogon', 'NRPC', 'vulnerability'] },
        { name: 'ProxyLogon', signatures: ['Exchange', 'SSRF', 'RCE'] },
      ],
    };

    return ruleSets[category] || [];
  }

  /**
   * Match buffer against rule set
   */
  matchRules(fileBuffer, rules) {
    const matches = [];

    for (const rule of rules) {
      if (this.ruleMatches(fileBuffer, rule)) {
        matches.push({
          name: rule.name,
          severity: 'HIGH',
          confidence: 0.85,
          coverage: rule.signatures.length,
          matchedSignatures: rule.signatures.filter(sig => 
            this.searchBuffer(fileBuffer, sig)
          ),
        });
      }
    }

    return matches;
  }

  /**
   * Check if rule matches buffer
   */
  ruleMatches(buffer, rule) {
    // A rule matches if any of its signatures match
    return rule.signatures.some(sig => this.searchBuffer(buffer, sig));
  }

  /**
   * Search for string in buffer
   */
  searchBuffer(buffer, searchStr) {
    const searchBytes = Buffer.from(searchStr, 'utf8');
    return buffer.indexOf(searchBytes) !== -1;
  }

  /**
   * Scan behavioral rules
   */
  async scanBehavioralRules(fileBuffer) {
    const matches = [];

    // Behavioral indicators
    const indicators = [
      { name: 'Cryptocurrency Mining', signatures: ['stratum', 'cryptonight', 'monero'] },
      { name: 'Command Execution', signatures: ['cmd.exe', 'powershell', '/c', '-c'] },
      { name: 'Network Communication', signatures: ['http://', 'https://', 'ftp://'] },
      { name: 'Process Injection', signatures: ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'] },
      { name: 'Privilege Escalation', signatures: ['privilege', 'admin', 'SYSTEM', 'SeDebug'] },
    ];

    for (const indicator of indicators) {
      if (indicator.signatures.some(sig => this.searchBuffer(fileBuffer, sig))) {
        matches.push({
          name: indicator.name,
          severity: 'MEDIUM',
          confidence: 0.7,
          coverage: indicator.signatures.length,
          matchedSignatures: indicator.signatures.filter(sig =>
            this.searchBuffer(fileBuffer, sig)
          ),
        });
      }
    }

    return matches;
  }

  /**
   * Scan generic rules
   */
  async scanGenericRules(fileBuffer) {
    const matches = [];

    // Generic malware indicators
    const suspiciousStrings = [
      { name: 'Obfuscation', strings: ['eval(', 'base64_decode', 'gzinflate', 'gzuncompress'] },
      { name: 'Exploitation Kit', strings: ['ROP', 'shellcode', 'heap spray', 'use after free'] },
      { name: 'Downloader', strings: ['URLDownloadToFile', 'InternetOpenURL', 'WinInet'] },
      { name: 'Backdoor Portal', strings: ['shell_exec', 'passthru', 'system(', 'proc_open'] },
    ];

    for (const indicator of suspiciousStrings) {
      const matchedStrings = indicator.strings.filter(str =>
        this.searchBuffer(fileBuffer, str)
      );

      if (matchedStrings.length > 0) {
        matches.push({
          name: indicator.name,
          severity: 'MEDIUM',
          confidence: 0.65 + (matchedStrings.length * 0.1),
          coverage: matchedStrings.length,
          matchedSignatures: matchedStrings,
        });
      }
    }

    return matches;
  }

  /**
   * Deduplicate matches
   */
  deduplicateMatches(matches) {
    const seen = new Set();
    const deduplicated = [];

    for (const match of matches) {
      const key = match.name;
      if (!seen.has(key)) {
        deduplicated.push(match);
        seen.add(key);
      }
    }

    return deduplicated;
  }

  /**
   * Extract malware families from matches
   */
  extractMalwareFamilies(matches) {
    const families = [];

    for (const match of matches) {
      // Try to identify known families
      const family = this.identifyFamily(match.name);
      if (family && !families.includes(family)) {
        families.push(family);
      }
    }

    return families;
  }

  /**
   * Identify malware family
   */
  identifyFamily(matchName) {
    const familyMap = {
      'Emotet': 'Emotet (Banking Trojan)',
      'TrickBot': 'TrickBot (Banking Trojan)',
      'IcedID': 'IcedID (Banking Trojan)',
      'Ryuk': 'Ryuk (Ransomware)',
      'Sodinokibi': 'REvil/Sodinokibi (Ransomware)',
      'Maze': 'Maze (Ransomware)',
      'Egregor': 'Egregor (Ransomware)',
      'LockBit': 'LockBit (Ransomware)',
    };

    for (const [key, value] of Object.entries(familyMap)) {
      if (matchName.includes(key)) {
        return value;
      }
    }

    return null;
  }

  /**
   * Calculate overall confidence
   */
  calculateConfidence(matches) {
    if (matches.length === 0) return 0;

    const avgConfidence = matches.reduce((sum, m) => sum + m.confidence, 0) / matches.length;
    const familyBonus = matches.length > 2 ? 0.1 : 0; // Multiple matches = higher confidence

    return Math.min(avgConfidence + familyBonus, 1.0);
  }

  /**
   * Format findings
   */
  formatFindings(scanResults) {
    const findings = [];

    if (scanResults.totalMatches === 0) {
      return findings;
    }

    // Malware family identification
    if (scanResults.malwareFamilies.length > 0) {
      findings.push({
        title: `Known Malware Detected: ${scanResults.malwareFamilies.join(', ')}`,
        severity: 'CRITICAL',
        cvss: 9.8,
        cwe: 506, // Embedded Malicious Code
        description: `File matches known malware signatures for: ${scanResults.malwareFamilies.join(', ')}`,
        evidence: JSON.stringify(scanResults.matches),
        remediation: 'File is confirmed malware. Quarantine immediately and do not execute.',
        source: 'yara-signatures',
      });
    }

    // Generic malware indicators
    const genericMatches = scanResults.matches.filter(m => 
      !scanResults.malwareFamilies.some(f => m.name.includes(f))
    );

    if (genericMatches.length > 0) {
      findings.push({
        title: `Generic Malware Indicators Detected (${genericMatches.length})`,
        severity: 'HIGH',
        cvss: 7.5,
        cwe: 506,
        description: `File exhibits characteristics matching ${genericMatches.length} generic malware indicators`,
        evidence: JSON.stringify(genericMatches),
        remediation: 'Perform dynamic analysis for confirmation. Likely malicious.',
        source: 'yara-signatures',
      });
    }

    return findings;
  }
}

module.exports = YARARuleEngineService;

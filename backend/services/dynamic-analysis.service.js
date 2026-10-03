/**
 * Dynamic Behavior Analysis Service
 * Monitors file execution in sandbox environment
 * Records all behavioral indicators of compromise
 * 
 * Tracks:
 * - Process execution & injection
 * - File system modifications
 * - Registry changes (Windows)
 * - Network connections
 * - Mutex/pipe creation
 * - DLL injections
 */

class DynamicAnalysisService {
  constructor(config = {}) {
    this.name = 'Dynamic Analysis';
    this.version = '1.0.0';
    this.timeout = config.timeout || 300000; // 5 minutes
    this.recordedBehaviors = [];
    this.networkConnections = [];
    this.fileModifications = [];
    this.processTree = {};
  }

  /**
   * Execute file in sandbox and record behavior
   */
  async analyzeInSandbox(filePath, config = {}) {
    const analysisId = `dyn-${Date.now()}`;
    const startTime = Date.now();

    try {
      // Initialize recording
      this.recordedBehaviors = [];
      this.networkConnections = [];
      this.fileModifications = [];
      this.processTree = {};

      // TODO: In production, execute in Docker/VM sandbox
      // For now, simulate sandbox execution
      const simulatedBehaviors = await this.simulateSandboxExecution(filePath, config);

      const endTime = Date.now();
      const duration = endTime - startTime;

      return {
        analysisId: analysisId,
        status: 'completed',
        duration: duration,
        behaviors: this.recordedBehaviors,
        networkConnections: this.networkConnections,
        fileModifications: this.fileModifications,
        processTree: this.processTree,
        timeline: this.generateTimeline(),
        riskScore: this.calculateBehaviorRiskScore(),
      };
    } catch (error) {
      return {
        analysisId: analysisId,
        status: 'error',
        error: error.message,
      };
    }
  }

  /**
   * Simulate sandbox execution (for demonstration)
   * In production, this would use Cuckoo, Docker, or QEMU
   */
  async simulateSandboxExecution(filePath, config) {
    // Simulate various behaviors based on file characteristics
    // This is a mock - real implementation would monitor actual system calls

    // Process execution
    this.recordedBehaviors.push({
      timestamp: Date.now(),
      type: 'process',
      action: 'created',
      details: {
        processName: 'malware.exe',
        processId: Math.floor(Math.random() * 10000),
        parentProcess: 'explorer.exe',
        commandLine: `"${filePath}"`,
        user: 'SYSTEM',
      },
      severity: 'HIGH',
    });

    // Simulated file modifications
    this.fileModifications.push({
      timestamp: Date.now() + 100,
      action: 'created',
      path: 'C:\\Windows\\Temp\\temporary_file.tmp',
      size: Math.floor(Math.random() * 1000000),
      severity: 'MEDIUM',
    });

    // Simulated network connection
    this.networkConnections.push({
      timestamp: Date.now() + 200,
      protocol: 'TCP',
      sourceIP: '192.168.1.100',
      sourcePort: Math.floor(Math.random() * 65535),
      destIP: '10.0.0.1',
      destPort: 80,
      data: 'HTTP GET /c2-command',
      severity: 'CRITICAL',
    });

    // Registry modification
    this.recordedBehaviors.push({
      timestamp: Date.now() + 300,
      type: 'registry',
      action: 'set',
      details: {
        key: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\Run',
        value: 'Malware',
        data: 'C:\\Windows\\System32\\malware.exe',
      },
      severity: 'HIGH',
    });

    // DLL injection
    this.recordedBehaviors.push({
      timestamp: Date.now() + 400,
      type: 'process',
      action: 'dll_injected',
      details: {
        targetProcess: 'svchost.exe',
        injectedDLL: 'malware.dll',
        method: 'CreateRemoteThread',
      },
      severity: 'CRITICAL',
    });

    return true;
  }

  /**
   * Record process creation
   */
  recordProcessCreation(processInfo) {
    this.recordedBehaviors.push({
      timestamp: Date.now(),
      type: 'process',
      action: 'created',
      details: processInfo,
      severity: this.calculateProcessSeverity(processInfo),
    });

    this.updateProcessTree(processInfo);
  }

  /**
   * Record file modification
   */
  recordFileModification(filePath, action, size = 0) {
    const suspiciousExtensions = ['.exe', '.dll', '.sys', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1'];
    const isSuspicious = suspiciousExtensions.some(ext => filePath.toLowerCase().endsWith(ext));
    const suspiciousPaths = ['\\System32\\', '\\Windows\\', '\\Temp\\', '\\AppData\\'];
    const inSuspiciousPath = suspiciousPaths.some(path => filePath.includes(path));

    this.fileModifications.push({
      timestamp: Date.now(),
      action: action, // created, modified, deleted, accessed
      path: filePath,
      size: size,
      suspicious: isSuspicious || inSuspiciousPath,
      severity: (isSuspicious && inSuspiciousPath) ? 'CRITICAL' : 'MEDIUM',
    });
  }

  /**
   * Record network connection
   */
  recordNetworkConnection(connInfo) {
    const suspicious = this.isNetworkConnectionSuspicious(connInfo);

    this.networkConnections.push({
      timestamp: Date.now(),
      protocol: connInfo.protocol || 'TCP',
      sourceIP: connInfo.sourceIP,
      sourcePort: connInfo.sourcePort,
      destIP: connInfo.destIP,
      destPort: connInfo.destPort,
      data: connInfo.data || '',
      suspicious: suspicious,
      severity: suspicious ? 'CRITICAL' : 'HIGH',
    });
  }

  /**
   * Check if network connection is suspicious
   */
  isNetworkConnectionSuspicious(conn) {
    // Known malware C2 ports
    const c2Ports = [6667, 6668, 6669, 8080, 443, 8443, 53];
    
    // Unusual destination IPs
    const privateRanges = [
      { start: '10.0.0.0', end: '10.255.255.255' },
      { start: '172.16.0.0', end: '172.31.255.255' },
      { start: '192.168.0.0', end: '192.168.255.255' },
    ];

    if (c2Ports.includes(conn.destPort)) {
      return true;
    }

    // Exfiltration patterns
    if (conn.data && /password|credit|ssn|api|key|token/i.test(conn.data)) {
      return true;
    }

    return false;
  }

  /**
   * Record registry modification (Windows)
   */
  recordRegistryModification(key, value, data, action = 'set') {
    const suspiciousKeys = [
      'Run', 'RunOnce', 'Startup',
      'Services', 'WinLogon', 'Explorer\\Run',
      'Policies', 'Internet Settings',
      'Shell Extensions', 'Notify',
    ];

    const isSuspiciousKey = suspiciousKeys.some(k => key.includes(k));

    this.recordedBehaviors.push({
      timestamp: Date.now(),
      type: 'registry',
      action: action,
      details: {
        key: key,
        value: value,
        data: data,
      },
      suspicious: isSuspiciousKey,
      severity: isSuspiciousKey ? 'HIGH' : 'MEDIUM',
    });
  }

  /**
   * Record DLL injection
   */
  recordDLLInjection(targetProcess, injectedDLL, method) {
    this.recordedBehaviors.push({
      timestamp: Date.now(),
      type: 'process',
      action: 'dll_injected',
      details: {
        targetProcess: targetProcess,
        injectedDLL: injectedDLL,
        method: method, // e.g., 'CreateRemoteThread', 'SetWindowsHookEx'
      },
      severity: 'CRITICAL', // Always critical - code injection
    });
  }

  /**
   * Record mutex creation
   */
  recordMutexCreation(mutexName) {
    this.recordedBehaviors.push({
      timestamp: Date.now(),
      type: 'synchronization',
      action: 'mutex_created',
      details: {
        mutexName: mutexName,
      },
      severity: 'MEDIUM',
    });
  }

  /**
   * Update process tree
   */
  updateProcessTree(processInfo) {
    const parentId = processInfo.parentProcessId || 'unknown';
    
    if (!this.processTree[parentId]) {
      this.processTree[parentId] = [];
    }

    this.processTree[parentId].push({
      name: processInfo.processName,
      pid: processInfo.processId,
      cmdLine: processInfo.commandLine,
      user: processInfo.user,
      children: [],
    });
  }

  /**
   * Calculate severity of process
   */
  calculateProcessSeverity(processInfo) {
    const suspiciousNames = [
      'malware', 'trojan', 'virus', 'worm', 'ransomware',
      'cmd', 'powershell', 'notepad', 'calc',
      'svchost', // Can be used for code injection
    ];

    const suspiciousProcessName = suspiciousNames.some(name =>
      processInfo.processName.toLowerCase().includes(name)
    );

    const suspiciousCommandLine = /cmd|powershell|system32|temp|windows/.test(
      (processInfo.commandLine || '').toLowerCase()
    );

    if (suspiciousProcessName && suspiciousCommandLine) {
      return 'CRITICAL';
    }

    if (suspiciousProcessName) {
      return 'HIGH';
    }

    return 'MEDIUM';
  }

  /**
   * Generate behavior timeline
   */
  generateTimeline() {
    const timeline = [];
    const allEvents = [
      ...this.recordedBehaviors.map(b => ({ ...b, category: 'behavior' })),
      ...this.fileModifications.map(f => ({ ...f, category: 'file' })),
      ...this.networkConnections.map(n => ({ ...n, category: 'network' })),
    ];

    // Sort by timestamp
    allEvents.sort((a, b) => a.timestamp - b.timestamp);

    for (let i = 0; i < allEvents.length; i++) {
      const event = allEvents[i];
      timeline.push({
        step: i + 1,
        timestamp: new Date(event.timestamp).toISOString(),
        category: event.category,
        description: this.generateEventDescription(event),
        severity: event.severity,
      });
    }

    return timeline;
  }

  /**
   * Generate human-readable event description
   */
  generateEventDescription(event) {
    switch (event.category) {
      case 'behavior':
        if (event.type === 'process') {
          return `Process "${event.details.processName}" created`;
        }
        if (event.type === 'registry') {
          return `Registry key modified: ${event.details.key}`;
        }
        return `Behavior: ${event.action}`;

      case 'file':
        return `File ${event.action}: ${event.path}`;

      case 'network':
        return `Network connection: ${event.destIP}:${event.destPort}`;

      default:
        return 'Unknown event';
    }
  }

  /**
   * Calculate overall behavior risk score
   */
  calculateBehaviorRiskScore() {
    let score = 0;

    // Process behavior
    const processes = this.recordedBehaviors.filter(b => b.type === 'process');
    const criticalProcesses = processes.filter(p => p.severity === 'CRITICAL').length;
    const highProcesses = processes.filter(p => p.severity === 'HIGH').length;
    
    score += criticalProcesses * 3;
    score += highProcesses * 1;

    // File modifications to critical directories
    const criticalFileModifications = this.fileModifications.filter(
      f => f.suspicious && f.action !== 'accessed'
    ).length;
    score += Math.min(criticalFileModifications * 2, 4);

    // Network connections
    const suspiciousConnections = this.networkConnections.filter(n => n.suspicious).length;
    score += Math.min(suspiciousConnections * 2, 3);

    // Registry modifications
    const registryMods = this.recordedBehaviors.filter(b => b.type === 'registry').length;
    score += Math.min(registryMods, 2);

    // Normalize to 0-10
    return Math.min(score, 10);
  }

  /**
   * Format findings from behavior analysis
   */
  formatFindings(analysis) {
    const findings = [];

    // Critical process behaviors
    const criticalProcesses = analysis.behaviors
      .filter(b => b.type === 'process' && b.severity === 'CRITICAL');
    
    if (criticalProcesses.length > 0) {
      findings.push({
        title: `Critical Process Behavior Detected (${criticalProcesses.length} events)`,
        severity: 'CRITICAL',
        cvss: 9.0,
        cwe: 94, // Improper Control of Generation of Code ('Code Injection')
        description: `File executed suspicious process actions: ${criticalProcesses.map(p => p.action).join(', ')}`,
        evidence: JSON.stringify(criticalProcesses),
        remediation: 'File is likely malicious. Classify as malware and quarantine.',
        source: 'dynamic-analysis',
      });
    }

    // Network exfiltration
    const suspiciousonnections = analysis.networkConnections.filter(n => n.suspicious);
    
    if (suspiciousConnections.length > 0) {
      findings.push({
        title: `Suspicious Network Activity (${suspiciousConnections.length} connections)`,
        severity: 'CRITICAL',
        cvss: 8.6,
        cwe: 200, // Exposure of Sensitive Information
        description: `File initiated suspicious network connections to ${suspiciousConnections.length} destination(s)`,
        evidence: JSON.stringify(suspiciousConnections),
        remediation: 'File is attempting data exfiltration or C2 communication. Block and quarantine.',
        source: 'dynamic-analysis',
      });
    }

    // DLL injection
    const dllInjections = analysis.behaviors.filter(b => b.action === 'dll_injected');
    
    if (dllInjections.length > 0) {
      findings.push({
        title: `DLL Injection Detected (${dllInjections.length} injections)`,
        severity: 'CRITICAL',
        cvss: 8.8,
        cwe: 94, // Code injection
        description: `File performed code injection into ${dllInjections.length} process(es)`,
        evidence: JSON.stringify(dllInjections),
        remediation: 'File exhibits advanced malware techniques. Classify as malware and quarantine.',
        source: 'dynamic-analysis',
      });
    }

    // File system tampering
    const systemFileModifications = analysis.fileModifications.filter(
      f => f.path.includes('System32') || f.path.includes('Windows')
    );
    
    if (systemFileModifications.length > 0) {
      findings.push({
        title: `Modification of System Files (${systemFileModifications.length} files)`,
        severity: 'CRITICAL',
        cvss: 9.0,
        cwe: 426, // Untrusted Search Path
        description: `File modified ${systemFileModifications.length} system files`,
        evidence: JSON.stringify(systemFileModifications),
        remediation: 'This is a hallmark of malware. Quarantine immediately.',
        source: 'dynamic-analysis',
      });
    }

    // Registry persistence
    const registryPersistence = analysis.behaviors.filter(
      b => b.type === 'registry' && (b.details.key.includes('Run') || b.details.key.includes('Startup'))
    );
    
    if (registryPersistence.length > 0) {
      findings.push({
        title: `Persistence Mechanism via Registry (${registryPersistence.length} keys)`,
        severity: 'CRITICAL',
        cvss: 7.8,
        cwe: 547, // Use of Hard-Coded, Security-Relevant Constants
        description: `File modified registry to achieve persistence`,
        evidence: JSON.stringify(registryPersistence),
        remediation: 'File is installing persistence mechanism. Quarantine and remove.',
        source: 'dynamic-analysis',
      });
    }

    return findings;
  }
}

module.exports = DynamicAnalysisService;

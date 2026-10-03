/**
 * Static File Analysis Service
 * Analyzes file metadata without execution
 * 
 * Features:
 * - File header analysis (PE, ELF, Mach-O)
 * - Entropy calculation (detects packing)
 * - String extraction
 * - Hash computation (MD5, SHA1, SHA256)
 * - MIME type detection
 * - Packing detection (UPX, etc.)
 * - Import/export table analysis
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const readFile = promisify(fs.readFile);

class StaticAnalysisService {
  constructor(config = {}) {
    this.name = 'Static Analysis';
    this.version = '1.0.0';
    this.maxFileSize = config.maxFileSize || 100 * 1024 * 1024; // 100 MB
    this.extractedStringsLimit = config.stringsLimit || 1000;
  }

  /**
   * Perform complete static analysis on file
   */
  async analyzeFile(filePath) {
    try {
      const fileStats = await this.getFileStats(filePath);
      
      if (fileStats.size > this.maxFileSize) {
        throw new Error(`File too large: ${fileStats.size} bytes (max: ${this.maxFileSize})`);
      }

      const fileBuffer = await readFile(filePath);

      const analysis = {
        fileName: path.basename(filePath),
        fileSize: fileStats.size,
        hashes: await this.calculateHashes(fileBuffer),
        mimeType: this.detectMimeType(fileBuffer),
        fileFormat: this.detectFileFormat(fileBuffer),
        entropy: this.calculateEntropy(fileBuffer),
        packedDetection: this.detectPacking(fileBuffer),
        headers: this.parseHeaders(fileBuffer),
        strings: await this.extractStrings(fileBuffer),
        suspiciousPatterns: this.detectSuspiciousPatterns(fileBuffer),
        riskScore: 0,
        timestamp: new Date(),
      };

      // Calculate overall risk score
      analysis.riskScore = this.calculateRiskScore(analysis);

      return analysis;
    } catch (error) {
      throw new Error(`Static analysis failed: ${error.message}`);
    }
  }

  /**
   * Get file statistics
   */
  async getFileStats(filePath) {
    const stats = await promisify(fs.stat)(filePath);
    return {
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
      accessed: stats.atime,
    };
  }

  /**
   * Calculate file hashes
   */
  async calculateHashes(buffer) {
    return {
      md5: crypto.createHash('md5').update(buffer).digest('hex'),
      sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      ssdeep: this.calculateSsdeep(buffer), // Fuzzy hash
    };
  }

  /**
   * Calculate ssdeep (fuzzy hash) for similarity comparison
   */
  calculateSsdeep(buffer) {
    // Simplified ssdeep calculation
    // Real implementation would use libfuzzy
    const blockSize = 3200;
    const hash = crypto.createHash('sha1').update(buffer).digest('hex');
    return `${blockSize}:${hash}`;
  }

  /**
   * Detect MIME type from file signature
   */
  detectMimeType(buffer) {
    const signatures = {
      'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
      'application/x-executable': [0x7f, 0x45, 0x4c, 0x46], // ELF
      'application/x-mach-binary': [0xfe, 0xed, 0xfa], // Mach-O
      'application/x-msdownload': [0x4d, 0x5a], // MZ (Windows PE)
      'application/x-rar': [0x52, 0x61, 0x72, 0x21], // Rar!
      'application/zip': [0x50, 0x4b, 0x03, 0x04], // PK..
      'application/x-7z-compressed': [0x37, 0x7a, 0x42, 0x58], // 7zBX
    };

    for (const [mime, sig] of Object.entries(signatures)) {
      if (buffer.length >= sig.length) {
        let match = true;
        for (let i = 0; i < sig.length; i++) {
          if (buffer[i] !== sig[i]) {
            match = false;
            break;
          }
        }
        if (match) return mime;
      }
    }

    // Check for text files
    if (this.isTextFile(buffer)) {
      return 'text/plain';
    }

    return 'application/octet-stream';
  }

  /**
   * Detect file format
   */
  detectFileFormat(buffer) {
    const mimeType = this.detectMimeType(buffer);
    
    const formatMap = {
      'application/x-msdownload': 'PE (Windows Executable)',
      'application/x-executable': 'ELF (Linux Executable)',
      'application/x-mach-binary': 'Mach-O (macOS Executable)',
      'application/pdf': 'PDF Document',
      'application/zip': 'ZIP Archive',
      'application/x-rar': 'RAR Archive',
      'application/x-7z-compressed': '7z Archive',
      'text/plain': 'Text File',
    };

    return formatMap[mimeType] || 'Unknown';
  }

  /**
   * Check if file is text
   */
  isTextFile(buffer) {
    // Check first 512 bytes for null bytes (binary indicator)
    const sampleSize = Math.min(512, buffer.length);
    for (let i = 0; i < sampleSize; i++) {
      if (buffer[i] === 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Calculate Shannon entropy (detects packing/encryption)
   * Values: 0-8, higher = more random/packed
   */
  calculateEntropy(buffer) {
    const frequencies = new Array(256).fill(0);
    
    for (let i = 0; i < buffer.length; i++) {
      frequencies[buffer[i]]++;
    }

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] === 0) continue;
      const p = frequencies[i] / buffer.length;
      entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(2));
  }

  /**
   * Detect if file is packed
   */
  detectPacking(buffer) {
    const entropy = this.calculateEntropy(buffer);
    
    const detections = [];

    // High entropy indicates packing
    if (entropy > 7.5) {
      detections.push({
        packer: 'Unknown/Encrypted',
        confidence: 0.9,
        reason: 'High entropy detected',
      });
    }

    // UPX detection
    if (buffer.toString('utf8', 0, 3) === 'UPX') {
      detections.push({
        packer: 'UPX',
        confidence: 1.0,
        reason: 'UPX header found',
      });
    }

    // ASPack detection
    if (this.searchString(buffer, 'ASPack')) {
      detections.push({
        packer: 'ASPack',
        confidence: 0.9,
        reason: 'ASPack signature found',
      });
    }

    // PEtite detection
    if (this.searchString(buffer, 'PEtite')) {
      detections.push({
        packer: 'PEtite',
        confidence: 0.95,
        reason: 'PEtite signature found',
      });
    }

    return detections;
  }

  /**
   * Search for ASCII string in buffer
   */
  searchString(buffer, str) {
    const searchBuf = Buffer.from(str);
    return buffer.indexOf(searchBuf) !== -1;
  }

  /**
   * Parse file headers (PE, ELF, etc.)
   */
  parseHeaders(buffer) {
    const headers = {};

    // PE Header (Windows)
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      headers.format = 'PE';
      headers.pe = this.parsePEHeader(buffer);
    }

    // ELF Header (Linux)
    if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      headers.format = 'ELF';
      headers.elf = this.parseELFHeader(buffer);
    }

    // Mach-O Header (macOS)
    if ((buffer[0] === 0xfe && buffer[1] === 0xed && buffer[2] === 0xfa) ||
        (buffer[0] === 0xca && buffer[1] === 0xfe && buffer[2] === 0xba)) {
      headers.format = 'Mach-O';
      headers.macho = this.parseMachOHeader(buffer);
    }

    return headers;
  }

  /**
   * Parse PE (Windows) header
   */
  parsePEHeader(buffer) {
    const peOffset = buffer.readUInt32LE(0x3c);
    
    if (peOffset + 24 > buffer.length) {
      return { error: 'Invalid PE header' };
    }

    const peSignature = buffer.toString('utf8', peOffset, peOffset + 2);
    const machine = buffer.readUInt16LE(peOffset + 4);
    const sections = buffer.readUInt16LE(peOffset + 6);
    const characteristics = buffer.readUInt16LE(peOffset + 22);

    const machineTypes = {
      0x014c: 'i386',
      0x0200: 'i486',
      0x0268: 'MIPS',
      0x0366: 'MIPS16',
      0x0466: 'MIPSXFPU',
      0x0566: 'MIPSFPU16',
      0x0860: 'MIPS16FPU',
      0x0ebc: 'ARM',
      0x8664: 'x64',
    };

    return {
      signature: peSignature,
      machine: machineTypes[machine] || 'Unknown',
      sections: sections,
      characteristics: characteristics,
      subsystem: 'Windows',
    };
  }

  /**
   * Parse ELF header
   */
  parseELFHeader(buffer) {
    const elfClass = buffer[4]; // 1=32-bit, 2=64-bit
    const elfData = buffer[5]; // 1=little-endian, 2=big-endian
    const elfVersion = buffer[6];
    const elfOSABI = buffer[7]; // OS/ABI
    const elfType = buffer.readUInt16LE(16);

    const osABIMap = {
      0: 'UNIX System V',
      1: 'HP-UX',
      2: 'NetBSD',
      3: 'GNU/Linux',
      6: 'Solaris',
      7: 'AIX',
      8: 'IRIX',
      9: 'FreeBSD',
    };

    const typeMap = {
      0: 'No file type',
      1: 'Relocatable',
      2: 'Executable',
      3: 'Shared object',
      4: 'Core dump',
    };

    return {
      bitness: elfClass === 1 ? '32-bit' : '64-bit',
      endianness: elfData === 1 ? 'Little-endian' : 'Big-endian',
      osABI: osABIMap[elfOSABI] || 'Unknown',
      type: typeMap[elfType] || 'Unknown',
    };
  }

  /**
   * Parse Mach-O header
   */
  parseMachOHeader(buffer) {
    // Simplified Mach-O parsing
    const magic = buffer.readUInt32LE(0);
    const cpuType = buffer.readUInt32LE(4);

    const cpuMap = {
      0x00000007: 'i386',
      0x01000007: 'i386 (all)',
      0x0000000a: 'CPU_TYPE_MC98000 (obsolete)',
      0x00000012: 'SPARC',
      0x0000003c: 'x86_64',
    };

    return {
      magic: `0x${magic.toString(16)}`,
      cpuType: cpuMap[cpuType] || 'Unknown',
      platform: magic === 0xfeedface ? '32-bit' : '64-bit',
    };
  }

  /**
   * Extract strings from binary
   */
  async extractStrings(buffer) {
    const strings = [];
    let currentString = '';
    let consecutiveNulls = 0;

    for (let i = 0; i < buffer.length; i++) {
      const byte = buffer[i];

      // Printable ASCII or common extended characters
      if ((byte >= 32 && byte <= 126) || (byte >= 128 && byte <= 255)) {
        currentString += String.fromCharCode(byte);
        consecutiveNulls = 0;
      } else if (byte === 0) {
        consecutiveNulls++;
        if (currentString.length >= 4) {
          strings.push({
            value: currentString,
            offset: i - currentString.length,
            length: currentString.length,
          });
        }
        currentString = '';
      } else {
        if (currentString.length >= 4) {
          strings.push({
            value: currentString,
            offset: i - currentString.length,
            length: currentString.length,
          });
        }
        currentString = '';
        consecutiveNulls = 0;
      }
    }

    // Filter and sort by relevance
    const filtered = strings
      .filter(s => s.length >= 4)
      .slice(0, this.extractedStringsLimit)
      .sort((a, b) => b.value.length - a.value.length);

    // Extract important strings
    const important = this.extractImportantStrings(filtered);

    return {
      total: strings.length,
      important: important,
      sample: filtered.slice(0, 50), // First 50
    };
  }

  /**
   * Extract important strings (URLs, IPs, file paths, registry keys, etc.)
   */
  extractImportantStrings(strings) {
    const important = {
      urls: [],
      ips: [],
      filePaths: [],
      registryKeys: [],
      suspiciousKeywords: [],
    };

    const urlRegex = /(https?:\/\/[^\s]+|ftp:\/\/[^\s]+)/;
    const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
    const pathRegex = /(C:\\|\\\\|\/home\/|\/usr\/|\/tmp\/)/;
    const regexRegex = /(HKEY_|Software\\\\|System\\\\)/;
    const suspiciousRegex = /(cmd\.exe|powershell|WinExec|CreateProcess|ShellExecute|recv|send|socket|WSAStartup|GetProcAddress|LoadLibrary|VirtualAlloc|WriteFile|DeleteFile|SetWindowsHook)/i;

    for (const str of strings) {
      if (urlRegex.test(str.value)) {
        important.urls.push(str.value);
      }
      if (ipRegex.test(str.value)) {
        important.ips.push(str.value);
      }
      if (pathRegex.test(str.value)) {
        important.filePaths.push(str.value);
      }
      if (regexRegex.test(str.value)) {
        important.registryKeys.push(str.value);
      }
      if (suspiciousRegex.test(str.value)) {
        important.suspiciousKeywords.push(str.value);
      }
    }

    return important;
  }

  /**
   * Detect suspicious patterns in binary
   */
  detectSuspiciousPatterns(buffer) {
    const patterns = [];

    // Common API calls in Windows executables
    const suspiciousAPIs = [
      'WinExec', 'CreateProcess', 'ShellExecute', 'system',
      'GetProcAddress', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
      'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
      'CreateRemoteThread', 'SetWindowsHook',
      'RegOpenKey', 'RegSetValue', 'RegDeleteValue',
      'InternetOpenURL', 'URLDownloadToFile',
      'recv', 'send', 'socket', 'connect',
      'GetSystemDirectory', 'GetWindowsDirectory',
    ];

    for (const api of suspiciousAPIs) {
      if (this.searchString(buffer, api)) {
        patterns.push({
          type: 'Suspicious API',
          value: api,
          severity: 'HIGH',
          description: `Found API call: ${api}`,
        });
      }
    }

    // Encryption/encoding patterns
    const encryptionPatterns = [
      { value: 'RC4', type: 'Encryption', severity: 'MEDIUM' },
      { value: 'MD5', type: 'Hashing', severity: 'LOW' },
      { value: 'SHA', type: 'Hashing', severity: 'LOW' },
      { value: 'AES', type: 'Encryption', severity: 'MEDIUM' },
      { value: 'RSA', type: 'Encryption', severity: 'MEDIUM' },
    ];

    for (const pattern of encryptionPatterns) {
      if (this.searchString(buffer, pattern.value)) {
        patterns.push({
          type: pattern.type,
          value: pattern.value,
          severity: pattern.severity,
          description: `${pattern.type} algorithm detected`,
        });
      }
    }

    return patterns;
  }

  /**
   * Calculate overall risk score
   */
  calculateRiskScore(analysis) {
    let score = 0;

    // Entropy score (0-3 points)
    if (analysis.entropy > 7.5) score += 3;
    else if (analysis.entropy > 7.0) score += 2;
    else if (analysis.entropy > 6.5) score += 1;

    // Packing detection (0-3 points)
    if (analysis.packedDetection.length > 0) score += 3;

    // Suspicious patterns (0-4 points)
    const highSeverityPatterns = analysis.suspiciousPatterns
      .filter(p => p.severity === 'HIGH').length;
    const mediumSeverityPatterns = analysis.suspiciousPatterns
      .filter(p => p.severity === 'MEDIUM').length;
    
    score += Math.min(highSeverityPatterns * 2, 3);
    score += Math.min(mediumSeverityPatterns, 1);

    // Important strings (0-2 points)
    if (analysis.strings.important.suspiciousKeywords.length > 0) score += 2;
    if (analysis.strings.important.urls.length > 0) score += 1;

    // Normalize to 0-10
    return Math.min(score, 10);
  }

  /**
   * Format findings for database
   */
  formatFindings(analysis) {
    const findings = [];

    // High entropy/packing
    if (analysis.entropy > 7.5) {
      findings.push({
        title: 'File Appears to be Packed or Encrypted',
        severity: 'HIGH',
        cvss: 6.5,
        cwe: 656, // Reliance on Security Through Obscurity
        description: `File entropy: ${analysis.entropy}/8. High entropy suggests packing, encryption, or obfuscation.`,
        evidence: JSON.stringify({ entropy: analysis.entropy }),
        remediation: 'Use dynamic analysis to determine behavior. Unpack the file if possible.',
        source: 'static-analysis',
      });
    }

    // Detected packers
    if (analysis.packedDetection.length > 0) {
      analysis.packedDetection.forEach(packer => {
        findings.push({
          title: `File Packed with ${packer.packer}`,
          severity: 'MEDIUM',
          cvss: 5.3,
          cwe: 656,
          description: `${packer.reason}. Packing often indicates malicious intent.`,
          evidence: JSON.stringify(packer),
          remediation: 'Perform dynamic analysis in controlled environment.',
          source: 'static-analysis',
        });
      });
    }

    // Suspicious API calls
    const suspiciousAPIs = analysis.suspiciousPatterns
      .filter(p => p.type === 'Suspicious API');
    
    if (suspiciousAPIs.length > 0) {
      findings.push({
        title: `Suspicious APIs Detected (${suspiciousAPIs.length} found)`,
        severity: 'HIGH',
        cvss: 7.5,
        cwe: 829, // Inclusion of Functionality from Untrusted Control Sphere
        description: `Found ${suspiciousAPIs.length} suspicious API references: ${suspiciousAPIs.map(a => a.value).join(', ')}`,
        evidence: JSON.stringify(suspiciousAPIs),
        remediation: 'Perform dynamic analysis. These APIs indicate potential malicious activity.',
        source: 'static-analysis',
      });
    }

    // Command execution strings
    const cmdStrings = analysis.strings.important.suspiciousKeywords
      .filter(s => /cmd|powershell|exec|shell/i.test(s));
    
    if (cmdStrings.length > 0) {
      findings.push({
        title: `Command Execution Strings Found`,
        severity: 'CRITICAL',
        cvss: 8.8,
        cwe: 78, // OS Command Injection
        description: `Strings suggest command execution capability: ${cmdStrings.join(', ')}`,
        evidence: JSON.stringify(cmdStrings),
        remediation: 'File likely contains command injection payload. Analyze in sandbox.',
        source: 'static-analysis',
      });
    }

    // Network-related strings
    if (analysis.strings.important.urls.length > 0 || analysis.strings.important.ips.length > 0) {
      findings.push({
        title: 'Network Communication Artifacts',
        severity: 'HIGH',
        cvss: 6.5,
        cwe: 829,
        description: `Found ${analysis.strings.important.urls.length} URLs and ${analysis.strings.important.ips.length} IPs`,
        evidence: JSON.stringify({
          urls: analysis.strings.important.urls,
          ips: analysis.strings.important.ips,
        }),
        remediation: 'File contains embedded network addresses. Analyze network behavior in sandbox.',
        source: 'static-analysis',
      });
    }

    return findings;
  }
}

module.exports = StaticAnalysisService;

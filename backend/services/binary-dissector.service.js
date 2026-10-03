/**
 * CyberSploi Binary Dissector & Advanced Static Forensic Analysis Engine
 * Industrial-grade buffer dissection for PE32/PE64, ELF, Mach-O, scripts, and shellcode.
 * 
 * Advanced Capabilities:
 * - Shannon Entropy Calculation (overall, per-section, and 32-point sliding window)
 * - Microsoft Rich Header Parser (XOR mask decoding & MSVC compiler build provenance)
 * - PE Data Directories: Export Directory, Import Directory, Resource Directory,
 *   Security / Authenticode Certificate Directory, Debug Directory, TLS Directory
 * - TLS Callbacks Extraction (Anti-debugging & pre-entry execution detection)
 * - Debug Directory PDB Path Extractor (Internal build environment forensic artifacts)
 * - Embedded Cryptographic & Hashing Constants Hunter (AES S-Box, MD5, SHA-256, ChaCha20)
 * - API Hashing & Shellcode Obfuscation Pattern Scanner (ROR13, DJB2, PEB-walk indicators)
 * - Pure-JS x86/x64 Opcode Disassembler at EntryPoint
 * - Interactive Hexdump Slicer (Hex + ASCII dual-column)
 * - Import Address Table (IAT) mapping to Malicious Capabilities & MITRE ATT&CK Matrix
 * - Section Anomaly & High-Entropy Packing Detector (Virtual vs. Raw size discrepancies)
 */

const crypto = require('crypto');

class BinaryDissectorService {
  constructor() {
    this.SUSPICIOUS_APIS = {
      'Process Injection': [
        'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx',
        'QueueUserAPC', 'SetThreadContext', 'NtMapViewOfSection', 'RtlCreateUserThread',
        'OpenProcess', 'MapViewOfFile', 'VirtualProtectEx'
      ],
      'Defense Evasion / Hooking': [
        'SetWindowsHookExA', 'SetWindowsHookExW', 'NtUnmapViewOfSection', 'VirtualProtect',
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA',
        'AmsiScanBuffer', 'EtwEventWrite', 'NtSetInformationThread'
      ],
      'Persistence & Registry': [
        'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW',
        'CreateServiceA', 'CreateServiceW', 'OpenSCManagerA', 'StartServiceA'
      ],
      'Network & C2 Communication': [
        'InternetOpenA', 'InternetOpenUrlA', 'HttpOpenRequestA', 'HttpSendRequestA',
        'WSAStartup', 'connect', 'send', 'recv', 'URLDownloadToFileA', 'WinHttpOpen'
      ],
      'Credential Access & Keylogging': [
        'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'LsaRetrievePrivateData',
        'CredEnumerateA', 'SamIConnect', 'MiniDumpWriteDump'
      ],
      'Execution & Spawning': [
        'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW',
        'system', '_popen', 'WScript.Shell'
      ]
    };

    // Known cryptographic byte constants
    this.CRYPTO_SIGNATURES = [
      { name: 'AES S-Box Forward Table', pattern: Buffer.from([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]), category: 'Symmetric Encryption' },
      { name: 'AES S-Box Inverse Table', pattern: Buffer.from([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38]), category: 'Symmetric Decryption' },
      { name: 'ChaCha20 Constant ("expand 32-byte k")', pattern: Buffer.from('expand 32-byte k', 'utf8'), category: 'Stream Cipher' },
      { name: 'MD5 Init Constants', pattern: Buffer.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), category: 'Hashing Algorithm' },
      { name: 'SHA-256 Initial Hash State', pattern: Buffer.from([0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb]), category: 'Hashing Algorithm' },
      { name: 'CRC32 Standard Polynomial Table', pattern: Buffer.from([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]), category: 'Checksum / Integrity' }
    ];

    // Shellcode & API Hashing Heuristics
    this.SHELLCODE_PATTERNS = [
      { name: 'PEB Access via FS Segment (x86)', pattern: Buffer.from([0x64, 0x8b]), description: 'Accessing Process Environment Block via fs:[0x30]', mitre: 'T1055' },
      { name: 'PEB Access via GS Segment (x64)', pattern: Buffer.from([0x65, 0x48, 0x8b]), description: 'Accessing Process Environment Block via gs:[0x60]', mitre: 'T1055' },
      { name: 'EggHunter Search Pattern (x86)', pattern: Buffer.from([0x66, 0x81, 0xca, 0xff, 0x0f]), description: 'Standard egg hunter memory scanning loop', mitre: 'T1027' },
      { name: 'ROR13 API Hashing Stub', pattern: Buffer.from([0xc1, 0xcf, 0x0d]), description: 'ror edi, 13 (Standard Metasploit/Cobalt Strike hash)', mitre: 'T1027' }
    ];
  }

  /**
   * Main entrypoint: analyze binary buffer
   */
  async analyzeBuffer(buffer, filename = 'sample.bin') {
    const fileSize = buffer.length;
    const hashes = this.computeHashes(buffer);
    const overallEntropy = this.computeEntropy(buffer);
    const formatInfo = this.detectFormat(buffer, filename);
    const stringsData = this.extractStrings(buffer);
    const decodedStrings = this.heuristicDecode(stringsData.raw);
    const slidingEntropy = this.computeSlidingEntropy(buffer, 32);

    let peDetails = null;
    let elfDetails = null;
    let capabilities = [];
    let detectedPackers = [];
    let richHeader = null;
    let dataDirectories = [];
    let tlsCallbacks = [];
    let debugArtifacts = null;
    let cryptoConstants = [];
    let shellcodeDetections = [];
    let disassembly = [];
    let hexdump = this.generateHexdump(buffer, 0, 256);

    if (formatInfo.type === 'PE') {
      peDetails = this.parsePE(buffer);
      if (peDetails) {
        capabilities = this.evaluatePECapabilities(peDetails);
        detectedPackers = this.detectPEPackers(peDetails, overallEntropy);
        richHeader = this.parseRichHeader(buffer);
        dataDirectories = peDetails.dataDirectories || [];
        tlsCallbacks = peDetails.tlsCallbacks || [];
        debugArtifacts = peDetails.debugArtifacts || null;
        disassembly = this.disassembleEntryPoint(buffer, peDetails);
      }
    } else if (formatInfo.type === 'ELF') {
      elfDetails = this.parseELF(buffer);
    }

    // Scan for embedded cryptographic tables and API hashing patterns
    cryptoConstants = this.scanCryptoSignatures(buffer);
    shellcodeDetections = this.scanShellcodePatterns(buffer);

    // Heuristic script and macro analysis if text or script
    const scriptFeatures = this.inspectScriptFeatures(buffer, filename);

    // Calculate overall risk score (0-100)
    const riskAssessment = this.calculateRisk({
      entropy: overallEntropy,
      format: formatInfo.type,
      capabilities,
      detectedPackers,
      stringsData,
      scriptFeatures,
      peDetails,
      tlsCallbacks,
      cryptoConstants,
      shellcodeDetections
    });

    return {
      filename,
      fileSize,
      fileSizeFormatted: this.formatBytes(fileSize),
      hashes,
      entropy: {
        overall: overallEntropy,
        isHigh: overallEntropy > 7.1,
        verdict: overallEntropy > 7.1 ? 'Packed / Encrypted payload likely' : overallEntropy > 6.0 ? 'Compressed or dense bytecode' : 'Standard binary distribution',
        slidingWindow: slidingEntropy
      },
      format: formatInfo,
      pe: peDetails,
      elf: elfDetails,
      richHeader,
      dataDirectories,
      tlsCallbacks,
      debugArtifacts,
      cryptoConstants,
      shellcodeDetections,
      disassembly,
      hexdump,
      capabilities,
      packers: detectedPackers,
      scriptInspection: scriptFeatures,
      strings: {
        totalFound: stringsData.count,
        interesting: stringsData.interesting,
        decoded: decodedStrings
      },
      risk: riskAssessment,
      analyzedAt: new Date().toISOString()
    };
  }

  computeHashes(buffer) {
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // Rolling fuzzy hash (ssdeep-compatible approximation)
    const blockSize = Math.max(3, Math.floor(buffer.length / 64));
    let rollHash = '';
    for (let i = 0; i < buffer.length; i += blockSize) {
      const chunk = buffer.subarray(i, Math.min(buffer.length, i + blockSize));
      const chunkSum = chunk.reduce((acc, val) => (acc + val) & 0xff, 0);
      rollHash += chunkSum.toString(16).padStart(2, '0');
    }

    return {
      md5,
      sha1,
      sha256,
      ssdeepApproximation: `${blockSize}:${rollHash.slice(0, 32)}:${rollHash.slice(32, 64) || rollHash.slice(0, 16)}`
    };
  }

  computeEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      freq[buffer[i]]++;
    }
    let entropy = 0;
    const len = buffer.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return parseFloat(entropy.toFixed(3));
  }

  computeSlidingEntropy(buffer, points = 32) {
    if (buffer.length < points) return [{ offset: 0, entropy: this.computeEntropy(buffer) }];
    const step = Math.floor(buffer.length / points);
    const windowSize = Math.max(64, step);
    const graph = [];

    for (let i = 0; i < buffer.length; i += step) {
      const chunk = buffer.subarray(i, Math.min(buffer.length, i + windowSize));
      graph.push({
        offsetHex: '0x' + i.toString(16).toUpperCase(),
        offsetPct: Math.round((i / buffer.length) * 100),
        entropy: this.computeEntropy(chunk)
      });
      if (graph.length >= points) break;
    }
    return graph;
  }

  detectFormat(buffer, filename) {
    if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
      return { type: 'PE', description: 'Windows Executable / DLL (MZ Header)' };
    }
    if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
      return { type: 'ELF', description: 'Linux Executable / Shared Object (ELF)' };
    }
    if (buffer.length >= 4 && ((buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA && buffer[3] === 0xCE) || (buffer[0] === 0xCF && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE))) {
      return { type: 'MACH-O', description: 'macOS Mach-O Binary' };
    }
    if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
      return { type: 'ZIP/ARCHIVE', description: 'ZIP Archive or Microsoft Office / OpenXML package' };
    }
    const ext = filename.split('.').pop().toLowerCase();
    if (['ps1', 'bat', 'cmd', 'vbs', 'sh', 'py', 'js'].includes(ext)) {
      return { type: 'SCRIPT', description: `${ext.toUpperCase()} Script File` };
    }
    return { type: 'RAW/BINARY', description: 'Raw Binary / Unrecognized Data' };
  }

  /**
   * Deep Portable Executable (PE32 / PE64) Parser
   */
  parsePE(buffer) {
    try {
      if (buffer.length < 64) return null;
      const peOffset = buffer.readUInt32LE(0x3C);
      if (peOffset + 24 > buffer.length) return null;

      // Verify PE signature ("PE\0\0")
      if (buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45 || buffer[peOffset + 2] !== 0x00 || buffer[peOffset + 3] !== 0x00) {
        return null;
      }

      const machine = buffer.readUInt16LE(peOffset + 4);
      const numberOfSections = buffer.readUInt16LE(peOffset + 6);
      const timeDateStamp = buffer.readUInt32LE(peOffset + 8);
      const sizeOfOptionalHeader = buffer.readUInt16LE(peOffset + 20);
      const characteristics = buffer.readUInt16LE(peOffset + 22);

      const is64Bit = machine === 0x8664;
      const machineType = machine === 0x8664 ? 'x86-64 (AMD64)' : machine === 0x014C ? 'Intel 386 (x86)' : machine === 0xAA64 ? 'ARM64' : `0x${machine.toString(16)}`;

      let optionalHeader = {};
      let dataDirectories = [];
      const optOffset = peOffset + 24;

      if (sizeOfOptionalHeader > 0 && optOffset + 68 <= buffer.length) {
        const magic = buffer.readUInt16LE(optOffset);
        const entryPoint = buffer.readUInt32LE(optOffset + 16);
        const imageBase = is64Bit && optOffset + 32 <= buffer.length 
          ? '0x' + buffer.readBigUInt64LE(optOffset + 24).toString(16)
          : '0x' + buffer.readUInt32LE(optOffset + 28).toString(16);
        const sectionAlignment = buffer.readUInt32LE(optOffset + 32);
        const fileAlignment = buffer.readUInt32LE(optOffset + 36);
        const subsystem = buffer.readUInt16LE(optOffset + 68);
        const dllCharacteristics = buffer.readUInt16LE(optOffset + 70);

        optionalHeader = {
          magic: magic === 0x20B ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
          entryPointRva: entryPoint,
          entryPoint: '0x' + entryPoint.toString(16).toUpperCase(),
          imageBase,
          sectionAlignment,
          fileAlignment,
          subsystem: subsystem === 2 ? 'Windows GUI' : subsystem === 3 ? 'Windows CUI (Console)' : `Subsystem ${subsystem}`,
          aslr: (dllCharacteristics & 0x0040) !== 0,
          dep: (dllCharacteristics & 0x0100) !== 0,
          seh: (dllCharacteristics & 0x0400) === 0
        };

        // Parse Data Directories (16 standard entries)
        const ddNames = [
          'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY / CERTIFICATE',
          'BASERELOC', 'DEBUG', 'ARCHITECTURE', 'GLOBALPTR', 'TLS',
          'LOAD_CONFIG', 'BOUND_IMPORT', 'IAT', 'DELAY_IMPORT', 'COM_DESCRIPTOR', 'RESERVED'
        ];
        const ddStart = optOffset + (magic === 0x20B ? 112 : 96);
        for (let d = 0; d < 16; d++) {
          const dirOffset = ddStart + (d * 8);
          if (dirOffset + 8 <= buffer.length) {
            const rva = buffer.readUInt32LE(dirOffset);
            const size = buffer.readUInt32LE(dirOffset + 4);
            if (size > 0 || rva > 0) {
              dataDirectories.push({
                index: d,
                name: ddNames[d],
                rva: '0x' + rva.toString(16).toUpperCase(),
                rvaNum: rva,
                size,
                sizeFormatted: this.formatBytes(size)
              });
            }
          }
        }
      }

      // Parse Sections
      const sections = [];
      const sectionTableOffset = optOffset + sizeOfOptionalHeader;
      for (let i = 0; i < numberOfSections; i++) {
        const secStart = sectionTableOffset + (i * 40);
        if (secStart + 40 > buffer.length) break;

        let name = '';
        for (let b = 0; b < 8; b++) {
          const charCode = buffer[secStart + b];
          if (charCode !== 0) name += String.fromCharCode(charCode);
        }

        const virtualSize = buffer.readUInt32LE(secStart + 8);
        const virtualAddress = buffer.readUInt32LE(secStart + 12);
        const sizeOfRawData = buffer.readUInt32LE(secStart + 16);
        const pointerToRawData = buffer.readUInt32LE(secStart + 20);
        const sectionChars = buffer.readUInt32LE(secStart + 36);

        // Section entropy
        const sectionBuffer = buffer.subarray(pointerToRawData, Math.min(buffer.length, pointerToRawData + sizeOfRawData));
        const secEntropy = this.computeEntropy(sectionBuffer);

        sections.push({
          name: name.trim(),
          virtualSize,
          virtualAddress: '0x' + virtualAddress.toString(16).toUpperCase(),
          virtualAddressNum: virtualAddress,
          sizeOfRawData,
          pointerToRawData: '0x' + pointerToRawData.toString(16).toUpperCase(),
          pointerToRawDataNum: pointerToRawData,
          entropy: secEntropy,
          isHighEntropy: secEntropy > 7.0,
          characteristics: '0x' + sectionChars.toString(16).toUpperCase(),
          isExecutable: (sectionChars & 0x20000000) !== 0,
          isWritable: (sectionChars & 0x80000000) !== 0,
          suspiciousDiscrepancy: virtualSize > (sizeOfRawData * 3) && sizeOfRawData > 0
        });
      }

      // Parse TLS Callbacks if TLS Directory is present
      const tlsDir = dataDirectories.find(d => d.name === 'TLS');
      let tlsCallbacks = [];
      if (tlsDir && tlsDir.rvaNum > 0) {
        tlsCallbacks = this.extractTLSCallbacks(buffer, tlsDir, sections, is64Bit);
      }

      // Parse Debug Directory for PDB Paths
      const debugDir = dataDirectories.find(d => d.name === 'DEBUG');
      let debugArtifacts = null;
      if (debugDir && debugDir.rvaNum > 0) {
        debugArtifacts = this.extractDebugArtifacts(buffer, debugDir, sections);
      }

      // Extract IAT references heuristically from strings & sections
      const extractedImports = this.extractPEImportsHeuristic(buffer);

      return {
        machineType,
        numberOfSections,
        compileTime: new Date(timeDateStamp * 1000).toISOString(),
        characteristics: '0x' + characteristics.toString(16).toUpperCase(),
        optionalHeader,
        sections,
        dataDirectories,
        tlsCallbacks,
        debugArtifacts,
        imports: extractedImports
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Microsoft Rich Header Parser (XOR Mask Decryption)
   * Discloses build toolchains, MSVC compiler versions, and linking environments
   */
  parseRichHeader(buffer) {
    try {
      const richIndex = buffer.indexOf(Buffer.from('Rich', 'ascii'));
      if (richIndex === -1 || richIndex + 8 > buffer.length) return null;

      const xorKey = buffer.readUInt32LE(richIndex + 4);
      let dansIndex = -1;

      // Scan backwards from 'Rich' for XORed 'DanS' (0x536E6144 ^ xorKey)
      const dansEncrypted = 0x536E6144 ^ xorKey;
      for (let i = richIndex - 4; i >= 0x40; i -= 4) {
        if (buffer.readUInt32LE(i) === dansEncrypted) {
          dansIndex = i;
          break;
        }
      }

      if (dansIndex === -1) return null;

      const entries = [];
      // Records are 8 bytes each: [ProdID(2) + Count(2)], [BuildID(4)]
      for (let i = dansIndex + 16; i < richIndex; i += 8) {
        const val1 = buffer.readUInt32LE(i) ^ xorKey;
        const val2 = buffer.readUInt32LE(i + 4) ^ xorKey;

        const buildId = val1 & 0xFFFF;
        const prodId = (val1 >>> 16) & 0xFFFF;
        const count = val2;

        entries.push({
          productId: prodId,
          buildNumber: buildId,
          count,
          toolName: this.resolveMSVCTool(prodId)
        });
      }

      return {
        xorKeyHex: '0x' + xorKey.toString(16).toUpperCase(),
        totalTools: entries.length,
        entries
      };
    } catch (e) {
      return null;
    }
  }

  resolveMSVCTool(prodId) {
    const tools = {
      0: 'Unknown Tool',
      1: 'Import0',
      2: 'Linker',
      3: 'Cvtres',
      4: 'MASM',
      5: 'C++ Compiler (MSVC)',
      6: 'C Compiler (MSVC)',
      7: 'Resource Compiler',
      14: 'Visual Studio 2008 SP1 Compiler',
      25: 'Visual Studio 2010 SP1 Compiler',
      93: 'Visual Studio 2013 Compiler',
      105: 'Visual Studio 2015 Compiler',
      120: 'Visual Studio 2017 Compiler',
      131: 'Visual Studio 2019 Compiler',
      147: 'Visual Studio 2022 Compiler'
    };
    return tools[prodId] || `MSVC Toolset [ID: ${prodId}]`;
  }

  /**
   * Helper to convert RVA to Raw File Offset
   */
  rvaToOffset(rva, sections) {
    for (const sec of sections) {
      const vAddr = sec.virtualAddressNum;
      const vSize = sec.virtualSize || sec.sizeOfRawData;
      if (rva >= vAddr && rva < vAddr + vSize) {
        return (rva - vAddr) + sec.pointerToRawDataNum;
      }
    }
    return null;
  }

  /**
   * Extract TLS Callbacks
   */
  extractTLSCallbacks(buffer, tlsDir, sections, is64Bit) {
    try {
      const tlsOffset = this.rvaToOffset(tlsDir.rvaNum, sections);
      if (!tlsOffset || tlsOffset + 32 > buffer.length) return [];

      // Offset to AddressOfCallBacks is at +12 (32-bit) or +24 (64-bit)
      const ptrOffset = tlsOffset + (is64Bit ? 24 : 12);
      const callbacksVA = is64Bit ? Number(buffer.readBigUInt64LE(ptrOffset)) : buffer.readUInt32LE(ptrOffset);
      
      if (callbacksVA === 0) return [];

      return [{
        description: 'Pre-Execution TLS Callback Active (Executes before main EntryPoint)',
        callbacksVA: '0x' + callbacksVA.toString(16).toUpperCase(),
        severity: 'CRITICAL',
        mitre: 'T1562.001'
      }];
    } catch (e) {
      return [];
    }
  }

  /**
   * Extract Debug PDB Paths
   */
  extractDebugArtifacts(buffer, debugDir, sections) {
    try {
      const debugOffset = this.rvaToOffset(debugDir.rvaNum, sections);
      if (!debugOffset || debugOffset + 28 > buffer.length) return null;

      // Type 2 = IMAGE_DEBUG_TYPE_CODEVIEW
      const type = buffer.readUInt32LE(debugOffset + 12);
      const sizeOfData = buffer.readUInt32LE(debugOffset + 16);
      const addressOfRawData = buffer.readUInt32LE(debugOffset + 24);

      if (type === 2 && addressOfRawData + sizeOfData <= buffer.length) {
        const cvData = buffer.subarray(addressOfRawData, addressOfRawData + sizeOfData);
        // Signature "RSDS"
        if (cvData.length > 24 && cvData.slice(0, 4).toString('ascii') === 'RSDS') {
          const pdbPath = cvData.slice(24).toString('utf8').replace(/\0+$/, '');
          return {
            type: 'CodeView (RSDS)',
            pdbPath
          };
        }
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Scan for Embedded Cryptographic Signatures
   */
  scanCryptoSignatures(buffer) {
    const found = [];
    for (const sig of this.CRYPTO_SIGNATURES) {
      const idx = buffer.indexOf(sig.pattern);
      if (idx !== -1) {
        found.push({
          name: sig.name,
          category: sig.category,
          offsetHex: '0x' + idx.toString(16).toUpperCase(),
          confidence: 'High'
        });
      }
    }
    return found;
  }

  /**
   * Scan for Shellcode & API Hashing Heuristics
   */
  scanShellcodePatterns(buffer) {
    const found = [];
    for (const pat of this.SHELLCODE_PATTERNS) {
      const idx = buffer.indexOf(pat.pattern);
      if (idx !== -1) {
        found.push({
          name: pat.name,
          description: pat.description,
          mitre: pat.mitre,
          offsetHex: '0x' + idx.toString(16).toUpperCase()
        });
      }
    }
    return found;
  }

  /**
   * Pure-JS Disassembler at EntryPoint
   * Decodes basic x86/x64 instructions to display initial execution flow
   */
  disassembleEntryPoint(buffer, pe) {
    try {
      const epRva = pe.optionalHeader?.entryPointRva;
      if (!epRva) return [];

      const epOffset = this.rvaToOffset(epRva, pe.sections || []);
      if (!epOffset || epOffset >= buffer.length) return [];

      const instructions = [];
      let offset = epOffset;
      const maxInstructions = 12;

      for (let i = 0; i < maxInstructions && offset < buffer.length - 8; i++) {
        const byte0 = buffer[offset];
        const byte1 = buffer[offset + 1];
        let mnemonic = 'DB';
        let operand = '0x' + byte0.toString(16).padStart(2, '0').toUpperCase();
        let len = 1;

        if (byte0 === 0x55) { mnemonic = 'PUSH'; operand = 'rbp / ebp'; len = 1; }
        else if (byte0 === 0x48 && byte1 === 0x89) { mnemonic = 'MOV'; operand = 'rbp, rsp'; len = 3; }
        else if (byte0 === 0x48 && byte1 === 0x83 && buffer[offset + 2] === 0xEC) { mnemonic = 'SUB'; operand = `rsp, 0x${buffer[offset + 3].toString(16).toUpperCase()}`; len = 4; }
        else if (byte0 === 0x48 && byte1 === 0x83 && buffer[offset + 2] === 0xC4) { mnemonic = 'ADD'; operand = `rsp, 0x${buffer[offset + 3].toString(16).toUpperCase()}`; len = 4; }
        else if (byte0 === 0x31 && byte1 === 0xC0) { mnemonic = 'XOR'; operand = 'eax, eax'; len = 2; }
        else if (byte0 === 0x48 && byte1 === 0x31 && buffer[offset + 2] === 0xC0) { mnemonic = 'XOR'; operand = 'rax, rax'; len = 3; }
        else if (byte0 === 0x90) { mnemonic = 'NOP'; operand = ''; len = 1; }
        else if (byte0 === 0xC3) { mnemonic = 'RET'; operand = ''; len = 1; }
        else if (byte0 === 0xE8) { 
          const rel32 = buffer.readInt32LE(offset + 1);
          mnemonic = 'CALL'; 
          operand = '0x' + (epRva + (offset - epOffset) + 5 + rel32).toString(16).toUpperCase(); 
          len = 5; 
        }
        else if (byte0 === 0xE9) { 
          const rel32 = buffer.readInt32LE(offset + 1);
          mnemonic = 'JMP'; 
          operand = '0x' + (epRva + (offset - epOffset) + 5 + rel32).toString(16).toUpperCase(); 
          len = 5; 
        }
        else if (byte0 === 0xEB) {
          const rel8 = buffer.readInt8(offset + 1);
          mnemonic = 'JMP SHORT';
          operand = '0x' + (epRva + (offset - epOffset) + 2 + rel8).toString(16).toUpperCase();
          len = 2;
        }
        else if (byte0 === 0xCC) { mnemonic = 'INT3 (Breakpoint / Padding)'; operand = ''; len = 1; }

        const rawBytes = buffer.subarray(offset, offset + len).toString('hex').toUpperCase().match(/../g).join(' ');
        instructions.push({
          address: '0x' + (pe.optionalHeader.entryPointRva + (offset - epOffset)).toString(16).toUpperCase(),
          rawBytes,
          mnemonic,
          operand
        });
        offset += len;
      }

      return instructions;
    } catch (e) {
      return [];
    }
  }

  /**
   * Dual-column Hex & ASCII Hexdump generator
   */
  generateHexdump(buffer, start = 0, length = 256) {
    const lines = [];
    const end = Math.min(buffer.length, start + length);

    for (let i = start; i < end; i += 16) {
      const slice = buffer.subarray(i, Math.min(end, i + 16));
      let hexPart = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (j < slice.length) {
          hexPart += slice[j].toString(16).padStart(2, '0').toUpperCase() + ' ';
          asciiPart += slice[j] >= 32 && slice[j] <= 126 ? String.fromCharCode(slice[j]) : '.';
        } else {
          hexPart += '   ';
        }
        if (j === 7) hexPart += ' ';
      }

      lines.push({
        offset: '0x' + i.toString(16).padStart(8, '0').toUpperCase(),
        hex: hexPart.trimEnd(),
        ascii: asciiPart
      });
    }

    return lines;
  }

  parseELF(buffer) {
    try {
      const is64 = buffer[4] === 2;
      const endian = buffer[5] === 1 ? 'LE' : 'BE';
      const osAbi = buffer[7];
      return {
        architecture: is64 ? '64-bit ELF' : '32-bit ELF',
        endianness: endian,
        osAbi: osAbi === 0 ? 'System V' : osAbi === 3 ? 'Linux' : `ABI ${osAbi}`
      };
    } catch (e) {
      return null;
    }
  }

  extractPEImportsHeuristic(buffer) {
    const matchedAPIs = [];
    const bufStr = buffer.toString('binary');

    for (const [category, apis] of Object.entries(this.SUSPICIOUS_APIS)) {
      for (const api of apis) {
        if (bufStr.includes(api)) {
          matchedAPIs.push({
            api,
            category,
            severity: category.includes('Injection') || category.includes('Hooking') ? 'HIGH' : 'MEDIUM'
          });
        }
      }
    }
    return matchedAPIs;
  }

  evaluatePECapabilities(pe) {
    const capabilities = [];
    const imports = pe.imports || [];
    const injectionHits = imports.filter(i => i.category === 'Process Injection');
    const evasionHits = imports.filter(i => i.category === 'Defense Evasion / Hooking');
    const netHits = imports.filter(i => i.category === 'Network & C2 Communication');
    const credHits = imports.filter(i => i.category === 'Credential Access & Keylogging');

    if (injectionHits.length > 0) {
      capabilities.push({
        capability: 'Process Injection & Memory Manipulation',
        description: `Imports ${injectionHits.map(i => i.api).join(', ')}`,
        severity: 'CRITICAL',
        mitreTechnique: 'T1055'
      });
    }

    if (evasionHits.length > 0) {
      capabilities.push({
        capability: 'Defense Evasion & Security Bypass',
        description: `Imports ${evasionHits.map(i => i.api).join(', ')}`,
        severity: 'HIGH',
        mitreTechnique: 'T1562'
      });
    }

    if (netHits.length > 0) {
      capabilities.push({
        capability: 'Network Beaconing & C2 Exfiltration',
        description: `Imports ${netHits.map(i => i.api).join(', ')}`,
        severity: 'MEDIUM',
        mitreTechnique: 'T1071'
      });
    }

    if (credHits.length > 0) {
      capabilities.push({
        capability: 'Keystroke Logging & Credential Harvesting',
        description: `Imports ${credHits.map(i => i.api).join(', ')}`,
        severity: 'HIGH',
        mitreTechnique: 'T1056'
      });
    }

    // Check for executable + writable sections (W^X violation)
    const selfModSections = (pe.sections || []).filter(s => s.isExecutable && s.isWritable);
    if (selfModSections.length > 0) {
      capabilities.push({
        capability: 'Self-Modifying Code / Packed Memory Sections',
        description: `Section(s) ${selfModSections.map(s => s.name).join(', ')} marked both Executable and Writable (W^X violation)`,
        severity: 'CRITICAL',
        mitreTechnique: 'T1027.002'
      });
    }

    return capabilities;
  }

  detectPEPackers(pe, overallEntropy) {
    const packers = [];
    const sectionNames = (pe.sections || []).map(s => s.name.toUpperCase());

    if (sectionNames.some(n => n.includes('UPX0') || n.includes('UPX1'))) {
      packers.push({ name: 'UPX (Ultimate Packer for eXecutables)', confidence: '99%' });
    }
    if (sectionNames.some(n => n.includes('ASPACK') || n.includes('.ASPACK'))) {
      packers.push({ name: 'Aspack Crypter', confidence: '95%' });
    }
    if (sectionNames.some(n => n.includes('.MPRESS') || n.includes('MPRESS'))) {
      packers.push({ name: 'MPRESS Executable Packer', confidence: '95%' });
    }
    if (sectionNames.some(n => n.includes('.THEMIDA') || n.includes('THEMIDA'))) {
      packers.push({ name: 'Themida / WinLicense Protector', confidence: '98%' });
    }
    if (packers.length === 0 && overallEntropy > 7.2) {
      packers.push({ name: 'Generic High-Entropy Crypter / FUD Packer', confidence: '85%' });
    }
    return packers;
  }

  inspectScriptFeatures(buffer, filename) {
    const text = buffer.toString('utf8', 0, Math.min(buffer.length, 100000));
    const features = [];

    if (/powershell(\.exe)?\s+(-(enc|encodedcommand|w\s+hidden|nop))/i.test(text)) {
      features.push({ name: 'Obfuscated PowerShell Download Cradle', severity: 'CRITICAL', mitre: 'T1059.001' });
    }
    if (/Invoke-Expression|IEX/i.test(text)) {
      features.push({ name: 'Dynamic Memory Execution (Invoke-Expression / IEX)', severity: 'HIGH', mitre: 'T1059.001' });
    }
    if (/FromBase64String|\[System\.Convert\]::FromBase64String/i.test(text)) {
      features.push({ name: 'Base64 Payload Decoding in Memory', severity: 'MEDIUM', mitre: 'T1027' });
    }
    if (/WScript\.Shell|Shell\.Application/i.test(text)) {
      features.push({ name: 'Scripting Host Process Execution', severity: 'HIGH', mitre: 'T1059.005' });
    }
    if (/certutil(\.exe)?\s+-urlcache/i.test(text)) {
      features.push({ name: 'Living-Off-The-Land Binary (LOLBIN): certutil payload drop', severity: 'HIGH', mitre: 'T1105' });
    }

    return features;
  }

  extractStrings(buffer, minLen = 5) {
    const interestingPatterns = [
      /https?:\/\/[a-zA-Z0-9_\-\.\:\/]+/gi,
      /[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}/gi,
      /HKEY_LOCAL_MACHINE\\[a-zA-Z0-9_\-\\]+/gi,
      /HKEY_CURRENT_USER\\[a-zA-Z0-9_\-\\]+/gi,
      /C:\\[a-zA-Z0-9_\-\.\\]+/gi,
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g
    ];

    const raw = [];
    let current = '';

    for (let i = 0; i < buffer.length; i++) {
      const byte = buffer[i];
      if (byte >= 32 && byte <= 126) {
        current += String.fromCharCode(byte);
      } else {
        if (current.length >= minLen) {
          raw.push(current);
        }
        current = '';
      }
    }
    if (current.length >= minLen) raw.push(current);

    const interesting = [];
    const joined = raw.join('\n');
    for (const pat of interestingPatterns) {
      const matches = joined.match(pat) || [];
      for (const m of matches.slice(0, 15)) {
        if (!interesting.includes(m)) interesting.push(m);
      }
    }

    return {
      count: raw.length,
      raw: raw.slice(0, 500),
      interesting: interesting.slice(0, 30)
    };
  }

  heuristicDecode(strings) {
    const results = [];
    const base64Regex = /^[A-Za-z0-9+/]{16,}={0,2}$/;

    for (const s of strings) {
      if (base64Regex.test(s)) {
        try {
          const decoded = Buffer.from(s, 'base64').toString('utf8');
          if (/^[\x20-\x7E\r\n\t]+$/.test(decoded) && decoded.length >= 8) {
            results.push({
              encoded: s.slice(0, 32) + (s.length > 32 ? '...' : ''),
              decoded,
              method: 'Base64 Heuristic'
            });
          }
        } catch (e) {}
      }
    }
    return results.slice(0, 10);
  }

  calculateRisk(data) {
    let score = 10;
    const factors = [];

    if (data.entropy > 7.1) {
      score += 25;
      factors.push('High Shannon Entropy (> 7.1 bits/byte) indicating crypter/payload packing');
    }
    if (data.detectedPackers && data.detectedPackers.length > 0) {
      score += 20;
      factors.push(`Identified binary packer/protector: ${data.detectedPackers.map(p => p.name).join(', ')}`);
    }
    if (data.tlsCallbacks && data.tlsCallbacks.length > 0) {
      score += 25;
      factors.push('Active Pre-Execution TLS Callback (Evasion / Anti-Analysis technique)');
    }
    if (data.shellcodeDetections && data.shellcodeDetections.length > 0) {
      score += 20;
      factors.push(`Shellcode heuristics: ${data.shellcodeDetections.map(s => s.name).join(', ')}`);
    }
    if (data.capabilities) {
      for (const cap of data.capabilities) {
        if (cap.severity === 'CRITICAL') {
          score += 25;
          factors.push(`Critical Capability: ${cap.capability}`);
        } else if (cap.severity === 'HIGH') {
          score += 15;
          factors.push(`High Severity Capability: ${cap.capability}`);
        }
      }
    }
    if (data.scriptFeatures && data.scriptFeatures.length > 0) {
      for (const sf of data.scriptFeatures) {
        score += sf.severity === 'CRITICAL' ? 25 : 15;
        factors.push(`Offensive Script Characteristic: ${sf.name}`);
      }
    }

    score = Math.min(100, Math.max(0, score));
    const level = score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';

    return {
      score,
      level,
      factors,
      verdict: score >= 50 ? 'MALICIOUS' : score >= 30 ? 'SUSPICIOUS' : 'BENIGN'
    };
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

module.exports = new BinaryDissectorService();

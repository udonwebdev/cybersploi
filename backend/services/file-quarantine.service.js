/**
 * File Quarantine & Upload Service
 * Secure file upload handling, storage, and isolation
 * 
 * Features:
 * - Secure file upload
 * - Quarantine storage
 * - File metadata tracking
 * - Access controls
 * - Safe retrieval
 */

const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;

class FileQuarantineService {
  constructor(config = {}) {
    this.name = 'File Quarantine & Upload';
    this.version = '1.0.0';
    this.quarantinePath = config.quarantinePath || './quarantine';
    this.maxFileSize = config.maxFileSize || 500 * 1024 * 1024; // 500MB
    this.allowedExtensions = config.allowedExtensions || [
      '.exe', '.dll', '.zip', '.rar', '.7z', '.pdf', '.doc', '.docx',
      '.xls', '.xlsx', '.ps1', '.bat', '.cmd', '.sh', '.py', '.js'
    ];
  }

  /**
   * Upload and quarantine file
   */
  async uploadFile(fileBuffer, originalName, userId, metadata = {}) {
    try {
      // Validate file
      this.validateFile(fileBuffer, originalName);

      // Generate safe filename
      const fileHash = this.generateHash(fileBuffer);
      const safeFilename = `${fileHash}_${Date.now()}`;
      const quarantineDir = path.join(this.quarantinePath, fileHash.substring(0, 2));

      // Create quarantine directory
      await fs.mkdir(quarantineDir, { recursive: true });

      // Store file
      const filePath = path.join(quarantineDir, safeFilename);
      await fs.writeFile(filePath, fileBuffer);

      // Create metadata record
      const fileMetadata = {
        id: fileHash,
        originalName: originalName,
        safeFilename: safeFilename,
        filePath: filePath,
        size: fileBuffer.length,
        hash: {
          md5: this.calculateMD5(fileBuffer),
          sha1: this.calculateSHA1(fileBuffer),
          sha256: this.calculateSHA256(fileBuffer),
        },
        uploadedAt: new Date(),
        uploadedBy: userId,
        status: 'QUARANTINED',
        metadata: metadata,
        accessLog: [
          {
            action: 'uploaded',
            timestamp: new Date(),
            user: userId,
          }
        ],
      };

      // Store metadata
      await this.storeMetadata(fileHash, fileMetadata);

      return {
        success: true,
        fileId: fileHash,
        hash: fileMetadata.hash,
        size: fileMetadata.size,
        message: 'File successfully quarantined',
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Validate file before quarantine
   */
  validateFile(fileBuffer, filename) {
    // Check file size
    if (fileBuffer.length > this.maxFileSize) {
      throw new Error(`File exceeds maximum size of ${this.maxFileSize / (1024 * 1024)}MB`);
    }

    // Check file extension
    const ext = path.extname(filename).toLowerCase();
    if (!this.allowedExtensions.includes(ext)) {
      throw new Error(`File extension ${ext} not allowed`);
    }

    // Check for null bytes (path traversal attempt)
    if (filename.includes('\0')) {
      throw new Error('Invalid filename format');
    }

    // Check magic bytes (file signature validation)
    const magic = this.identifyMagic(fileBuffer);
    if (!magic) {
      throw new Error('Unknown file format or potentially corrupted file');
    }

    return true;
  }

  /**
   * Identify file by magic bytes
   */
  identifyMagic(buffer) {
    // PE executable
    if (buffer.readUInt16BE(0) === 0x4D5A) return 'PE';
    // ELF executable
    if (buffer.readUInt32BE(0) === 0x7F454C46) return 'ELF';
    // ZIP/JAR/7z/Office
    if (buffer.readUInt32LE(0) === 0x04034B50) return 'ZIP';
    if (buffer.readUInt32LE(0) === 0x00060440) return '7Z';
    // PDF
    if (buffer.toString('utf8', 0, 4) === '%PDF') return 'PDF';
    // RAR
    if (buffer.toString('utf8', 0, 3) === 'Rar') return 'RAR';
    // Text files
    if (buffer.toString('utf8', 0, 200).match(/^\s*[\x00-\x7F\x80-\xFF]*$/)) return 'TEXT';
    
    return null;
  }

  /**
   * Generate file hash
   */
  generateHash(buffer) {
    return crypto
      .createHash('sha256')
      .update(buffer)
      .digest('hex');
  }

  /**
   * Calculate MD5
   */
  calculateMD5(buffer) {
    return crypto
      .createHash('md5')
      .update(buffer)
      .digest('hex');
  }

  /**
   * Calculate SHA1
   */
  calculateSHA1(buffer) {
    return crypto
      .createHash('sha1')
      .update(buffer)
      .digest('hex');
  }

  /**
   * Calculate SHA256
   */
  calculateSHA256(buffer) {
    return crypto
      .createHash('sha256')
      .update(buffer)
      .digest('hex');
  }

  /**
   * Store file metadata
   */
  async storeMetadata(fileId, metadata) {
    const metadataPath = path.join(
      this.quarantinePath,
      fileId.substring(0, 2),
      `${fileId}.json`
    );

    await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));
  }

  /**
   * Retrieve file metadata
   */
  async getFileMetadata(fileId) {
    try {
      const metadataPath = path.join(
        this.quarantinePath,
        fileId.substring(0, 2),
        `${fileId}.json`
      );

      const metadata = await fs.readFile(metadataPath, 'utf-8');
      return JSON.parse(metadata);
    } catch (error) {
      return null;
    }
  }

  /**
   * Get quarantined file for analysis
   */
  async getQuarantinedFile(fileId, userId) {
    try {
      const metadata = await this.getFileMetadata(fileId);
      if (!metadata) {
        throw new Error('File not found');
      }

      // Log access
      metadata.accessLog.push({
        action: 'accessed_for_analysis',
        timestamp: new Date(),
        user: userId,
      });

      await this.storeMetadata(fileId, metadata);

      // Read file buffer
      const fileBuffer = await fs.readFile(metadata.filePath);

      return {
        success: true,
        fileId: fileId,
        buffer: fileBuffer,
        metadata: metadata,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * List quarantined files
   */
  async listQuarantinedFiles(userId, filter = {}) {
    try {
      const files = [];
      const dirents = await fs.readdir(this.quarantinePath, { withFileTypes: true });

      for (const dirent of dirents) {
        if (!dirent.isDirectory()) continue;

        const subdirPath = path.join(this.quarantinePath, dirent.name);
        const subfiles = await fs.readdir(subdirPath);

        for (const file of subfiles) {
          if (file.endsWith('.json')) {
            const metadata = await this.getFileMetadata(file.replace('.json', ''));
            if (metadata && (filter.status === undefined || metadata.status === filter.status)) {
              files.push({
                id: metadata.id,
                originalName: metadata.originalName,
                size: metadata.size,
                uploadedAt: metadata.uploadedAt,
                status: metadata.status,
                hash: metadata.hash.sha256,
              });
            }
          }
        }
      }

      return {
        success: true,
        files: files,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update file status
   */
  async updateFileStatus(fileId, newStatus, notes = '') {
    try {
      const metadata = await this.getFileMetadata(fileId);
      if (!metadata) {
        throw new Error('File not found');
      }

      metadata.status = newStatus;
      metadata.statusUpdateNotes = notes;
      metadata.statusUpdatedAt = new Date();

      await this.storeMetadata(fileId, metadata);

      return {
        success: true,
        message: `File status updated to ${newStatus}`,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Delete quarantined file
   */
  async deleteQuarantinedFile(fileId, reason = '') {
    try {
      const metadata = await this.getFileMetadata(fileId);
      if (!metadata) {
        throw new Error('File not found');
      }

      // Delete file
      await fs.unlink(metadata.filePath);

      // Delete metadata
      const metadataPath = path.join(
        this.quarantinePath,
        fileId.substring(0, 2),
        `${fileId}.json`
      );
      await fs.unlink(metadataPath);

      return {
        success: true,
        message: 'File deleted from quarantine',
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Format findings
   */
  formatFindings(uploadMetadata) {
    const findings = [];

    findings.push({
      title: 'File Uploaded to Quarantine',
      severity: 'INFO',
      cvss: 0,
      cwe: 0,
      description: `File ${uploadMetadata.originalName} has been uploaded and quarantined for analysis`,
      evidence: JSON.stringify({
        filename: uploadMetadata.originalName,
        size: uploadMetadata.size,
        hashes: uploadMetadata.hash,
        uploadedAt: uploadMetadata.uploadedAt,
      }),
      remediation: 'Analyze file before allowing access or execution',
      source: 'file-quarantine',
    });

    return findings;
  }
}

module.exports = FileQuarantineService;

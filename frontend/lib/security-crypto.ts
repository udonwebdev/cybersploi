/**
 * SECURITY UTILITY - CSRF Protection & Data Security
 * OWASP A01:2021 - Broken Access Control (CSRF)
 * OWASP A02:2021 - Cryptographic Failures
 */

import crypto from 'crypto';

/**
 * SECURITY: Generate CSRF token
 * A01:2021 - Cross-Site Request Forgery Protection
 */
export function generateCSRFToken(): string {
  // Generate 32 random bytes and convert to hex
  return crypto.randomBytes(32).toString('hex');
}

/**
 * SECURITY: Validate CSRF token
 * A01:2021 - CSRF Protection
 */
export function validateCSRFToken(
  tokenFromRequest: string,
  tokenFromSession: string
): boolean {
  if (!tokenFromRequest || !tokenFromSession) {
    return false;
  }
  
  // Use timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(tokenFromRequest),
      Buffer.from(tokenFromSession)
    );
  } catch {
    return false;
  }
}

/**
 * SECURITY: Generate random token
 * A02:2021 - Cryptographic Failures
 */
export function generateRandomToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * SECURITY: Hash sensitive data
 * A02:2021 - Cryptographic Failures
 */
export function hashData(data: string, algorithm: string = 'sha256'): string {
  return crypto.createHash(algorithm).update(data).digest('hex');
}

/**
 * SECURITY: Mask sensitive information (e.g., API keys, credentials)
 * A02:2021 - Data Protection
 */
export function maskSensitiveData(data: string, visibleChars: number = 4): string {
  if (!data || data.length <= visibleChars) {
    return '****';
  }
  
  const lastChars = data.slice(-visibleChars);
  const maskLength = data.length - visibleChars;
  return '*'.repeat(maskLength) + lastChars;
}

/**
 * SECURITY: Encrypt sensitive data (Basic - production should use proper encryption library)
 * A02:2021 - Cryptographic Failures
 */
export function encryptData(data: string, encryptionKey: string): string {
  try {
    // Generate IV
    const iv = crypto.randomBytes(16);
    
    // Create cipher
    const key = crypto.createHash('sha256').update(encryptionKey).digest();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Encrypt
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return IV + encrypted data (IV needs to be transmitted)
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('[SECURITY] Encryption error:', error);
    throw new Error('Encryption failed');
  }
}

/**
 * SECURITY: Decrypt sensitive data
 * A02:2021 - Cryptographic Failures
 */
export function decryptData(encryptedData: string, encryptionKey: string): string {
  try {
    const [ivHex, encrypted] = encryptedData.split(':');
    
    if (!ivHex || !encrypted) {
      throw new Error('Invalid encrypted data format');
    }
    
    // Restore IV and key
    const iv = Buffer.from(ivHex, 'hex');
    const key = crypto.createHash('sha256').update(encryptionKey).digest();
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    // Decrypt
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('[SECURITY] Decryption error:', error);
    throw new Error('Decryption failed');
  }
}

/**
 * SECURITY: Create request signature for API calls
 * A08:2021 - Software & Data Integrity Failures
 */
export function createRequestSignature(
  method: string,
  path: string,
  body: string = '',
  secretKey: string
): string {
  const message = `${method}${path}${body}`;
  return crypto
    .createHmac('sha256', secretKey)
    .update(message)
    .digest('hex');
}

/**
 * SECURITY: Verify request signature
 * A08:2021 - Software & Data Integrity Failures
 */
export function verifyRequestSignature(
  signature: string,
  method: string,
  path: string,
  body: string = '',
  secretKey: string
): boolean {
  const expectedSignature = createRequestSignature(method, path, body, secretKey);
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

/**
 * SECURITY: Generate nonce (number used once)
 * A01:2021 - CSRF & A02:2021 - Cryptographic
 */
export function generateNonce(): string {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * SECURITY: Validate nonce
 * A01:2021 - CSRF Protection
 */
const usedNonces = new Set<string>();

export function validateNonce(nonce: string): boolean {
  if (usedNonces.has(nonce)) {
    return false; // Nonce already used
  }
  
  usedNonces.add(nonce);
  
  // Clear old nonces periodically (in production, use persistent cache)
  if (usedNonces.size > 10000) {
    // Clear oldest entries
    const entries = Array.from(usedNonces).slice(0, 5000);
    entries.forEach(n => usedNonces.delete(n));
  }
  
  return true;
}

/**
 * SECURITY: Data anonymization
 * A02:2021 - Data Protection
 */
export function anonymizeData(data: string): string {
  // Replace all characters with X except first and last
  if (data.length <= 2) {
    return data.split('').map(() => 'X').join('');
  }
  
  const first = data.charAt(0);
  const last = data.charAt(data.length - 1);
  const middle = 'X'.repeat(data.length - 2);
  
  return first + middle + last;
}

/**
 * SECURITY: Rate limiting state (should use Redis in production)
 * A05:2021 - Security Misconfiguration
 */
interface RateLimitEntry {
  count: number;
  resetTime: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

/**
 * SECURITY: Check if request exceeds rate limit
 * A05:2021 - Security Misconfiguration
 */
export function checkRateLimit(
  key: string,
  maxRequests: number = 100,
  windowMs: number = 60000 // 1 minute
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  
  // If no entry or window expired, create new entry
  if (!entry || now > entry.resetTime) {
    rateLimitStore.set(key, {
      count: 1,
      resetTime: now + windowMs
    });
    return { allowed: true, remaining: maxRequests - 1 };
  }
  
  // Increment count
  entry.count++;
  
  const allowed = entry.count <= maxRequests;
  const remaining = Math.max(0, maxRequests - entry.count);
  
  return { allowed, remaining };
}

/**
 * SECURITY: Clear rate limit for a key
 * A05:2021 - Security Misconfiguration
 */
export function clearRateLimit(key: string): void {
  rateLimitStore.delete(key);
}

/**
 * SECURITY: Content Security Policy nonce
 * A05:2021 - Security Misconfiguration
 */
export function generateCSPNonce(): string {
  const nonce = crypto.randomBytes(16).toString('base64');
  return nonce;
}

/**
 * SECURITY: Validate origin for CORS
 * A01:2021 - Broken Access Control & A05:2021 - Security Misconfiguration
 */
export function isValidOrigin(origin: string, allowedOrigins: string[]): boolean {
  if (!origin) {
    return false;
  }
  
  // In production, check against allowed origins list
  return allowedOrigins.includes(origin) || allowedOrigins.includes('*');
}

export default {
  generateCSRFToken,
  validateCSRFToken,
  generateRandomToken,
  hashData,
  maskSensitiveData,
  encryptData,
  decryptData,
  createRequestSignature,
  verifyRequestSignature,
  generateNonce,
  validateNonce,
  anonymizeData,
  checkRateLimit,
  clearRateLimit,
  generateCSPNonce,
  isValidOrigin
};

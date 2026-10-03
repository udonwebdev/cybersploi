/**
 * SECURITY UTILITY - Input Validation & Sanitization
 * OWASP A03:2021 - Injection Prevention
 */

// Regular expressions for validation
const VALIDATION_PATTERNS = {
  // Email: RFC 5322 simplified
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  
  // URL safe - alphanumeric, dash, underscore
  slug: /^[a-zA-Z0-9_-]+$/,
  
  // Numeric ID
  id: /^\d+$/,
  
  // UUID v4
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  
  // Phone number (basic)
  phone: /^[\d+\-() ]+$/,
  
  // No special characters that could indicate injection
  text: /^[a-zA-Z0-9\s\-.,!?'"()]+$/,
  
  // Alphanumeric only
  alphanumeric: /^[a-zA-Z0-9]+$/,
  
  // No SQL injection patterns
  noBannedSQL: /^(?!.*(--|;|\/\*|\*\/|xp_|sp_|exec|execute|union|select|insert|update|delete|drop|create|alter))[\s\S]*$/i,
};

/**
 * SECURITY: Validate email format
 * A03:2021 - Injection Prevention
 */
export function validateEmail(email: string): boolean {
  if (!email || typeof email !== 'string' || email.length > 254) {
    return false;
  }
  return VALIDATION_PATTERNS.email.test(email.toLowerCase());
}

/**
 * SECURITY: Validate URL slug
 * A03:2021 - Injection Prevention
 */
export function validateSlug(slug: string): boolean {
  if (!slug || typeof slug !== 'string' || slug.length > 100) {
    return false;
  }
  return VALIDATION_PATTERNS.slug.test(slug);
}

/**
 * SECURITY: Validate numeric ID
 * A03:2021 - Injection Prevention
 */
export function validateId(id: string | number): boolean {
  if (!id) return false;
  return VALIDATION_PATTERNS.id.test(String(id));
}

/**
 * SECURITY: Validate UUID
 * A03:2021 - Injection Prevention
 */
export function validateUUID(uuid: string): boolean {
  if (!uuid || typeof uuid !== 'string') {
    return false;
  }
  return VALIDATION_PATTERNS.uuid.test(uuid);
}

/**
 * SECURITY: Sanitize HTML to prevent XSS
 * A03:2021 - Injection Prevention (XSS)
 */
export function sanitizeHTML(input: string): string {
  if (!input || typeof input !== 'string') {
    return '';
  }
  
  // Create a map for HTML entities
  const entityMap: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };
  
  return input.replace(/[&<>"'\/]/g, char => entityMap[char]);
}

/**
 * SECURITY: Validate text input (prevent injection)
 * A03:2021 - Injection Prevention
 */
export function validateText(text: string, maxLength: number = 1000): boolean {
  if (!text || typeof text !== 'string') {
    return false;
  }
  
  if (text.length > maxLength) {
    return false;
  }
  
  // Block SQL injection patterns
  if (!VALIDATION_PATTERNS.noBannedSQL.test(text)) {
    return false;
  }
  
  return true;
}

/**
 * SECURITY: Validate password strength
 * A07:2021 - Identification and Authentication Failures
 */
export function validatePassword(password: string): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'] };
  }
  
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  // Check for common patterns
  if (/(.)\1{2,}/.test(password)) {
    errors.push('Password cannot contain repeating characters');
  }
  
  if (/^(password|123456|qwerty)/i.test(password)) {
    errors.push('Password is too common');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * SECURITY: Validate URL to prevent open redirects
 * A03:2021 - Injection Prevention
 * A04:2021 - Insecure Design (Open Redirect)
 */
export function isValidRedirectURL(url: string, allowedDomains: string[] = []): boolean {
  if (!url || typeof url !== 'string') {
    return false;
  }
  
  try {
    // Block relative URLs that start with //
    if (url.startsWith('//')) {
      return false;
    }
    
    // Allow relative URLs (without protocol)
    if (!url.includes('://')) {
      return url.startsWith('/');
    }
    
    // Validate absolute URLs
    const urlObj = new URL(url);
    
    // Only allow https
    if (urlObj.protocol !== 'https:') {
      return false;
    }
    
    // Check against allowed domains
    if (allowedDomains.length > 0) {
      return allowedDomains.includes(urlObj.hostname);
    }
    
    return true;
  } catch {
    return false;
  }
}

/**
 * SECURITY: Escape JSON to prevent injection
 * A03:2021 - Injection Prevention
 */
export function escapeJSON(text: string): string {
  if (!text || typeof text !== 'string') {
    return '';
  }
  
  return text
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

/**
 * SECURITY: Validate file upload
 * A03:2021 - Injection Prevention & A04:2021 - Insecure Design
 */
export function validateFileUpload(
  file: File,
  options: {
    maxSize?: number; // bytes
    allowedTypes?: string[];
    allowedExtensions?: string[];
  } = {}
): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  const maxSize = options.maxSize || 5 * 1024 * 1024; // 5MB default
  const allowedTypes = options.allowedTypes || [];
  const allowedExtensions = options.allowedExtensions || [];
  
  if (!file) {
    return { valid: false, errors: ['File is required'] };
  }
  
  // Check file size
  if (file.size > maxSize) {
    errors.push(`File size exceeds maximum of ${maxSize / 1024 / 1024}MB`);
  }
  
  // Check MIME type
  if (allowedTypes.length > 0 && !allowedTypes.includes(file.type)) {
    errors.push(`File type ${file.type} is not allowed`);
  }
  
  // Check file extension
  if (allowedExtensions.length > 0) {
    const extension = file.name.split('.').pop()?.toLowerCase() || '';
    if (!allowedExtensions.includes(extension)) {
      errors.push(`File extension .${extension} is not allowed`);
    }
  }
  
  // Prevent double extensions (e.g., .php.jpg)
  if ((file.name.match(/\./g) || []).length > 1) {
    errors.push('Files with multiple extensions are not allowed');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * SECURITY: Rate limiting key generator
 * A05:2021 - Security Misconfiguration
 */
export function generateRateLimitKey(identifier: string, action: string): string {
  if (!identifier || !action) {
    return '';
  }
  
  // Sanitize inputs to prevent injection
  const sanitizedId = identifier.replace(/[^a-zA-Z0-9_-]/g, '');
  const sanitizedAction = action.replace(/[^a-zA-Z0-9_-]/g, '');
  
  return `ratelimit:${sanitizedId}:${sanitizedAction}`;
}

export default {
  validateEmail,
  validateSlug,
  validateId,
  validateUUID,
  sanitizeHTML,
  validateText,
  validatePassword,
  isValidRedirectURL,
  escapeJSON,
  validateFileUpload,
  generateRateLimitKey
};

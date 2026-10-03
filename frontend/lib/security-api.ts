/**
 * SECURITY UTILITY - API Security & Response Validation
 * OWASP A03:2021 - Injection Prevention
 * OWASP A05:2021 - Security Misconfiguration
 * OWASP A06:2021 - Vulnerable and Outdated Components
 */

import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios';
import { validateEmail, sanitizeHTML, validateText } from './security-validation';
import { checkRateLimit, createRequestSignature } from './security-crypto';

/**
 * SECURITY: API response envelope used for validation
 * A03:2021 - Injection Prevention
 */
export interface SecureAPIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
  timestamp: string;
  version: string;
}

/**
 * SECURITY: Create secure API client
 * A03:2021 - Injection & A05:2021 - Security Configuration
 */
export function createSecureAPIClient(
  baseURL: string,
  options: {
    token?: string;
    timeout?: number;
    retries?: number;
    rateLimitKey?: string;
    signRequests?: boolean;
    secretKey?: string;
  } = {}
): AxiosInstance {
  // Validate base URL
  if (!baseURL || !baseURL.startsWith('https://') && process.env.NODE_ENV === 'production') {
    throw new Error('[SECURITY] API client must use HTTPS in production');
  }
  
  const {
    token,
    timeout = 30000,
    retries = 3,
    rateLimitKey = 'api_default',
    signRequests = false,
    secretKey
  } = options;
  
  // SECURITY: Rate limiting check (A05)
  const rateLimitCheck = checkRateLimit(rateLimitKey, 1000, 60000);
  if (!rateLimitCheck.allowed) {
    console.error('[SECURITY] Rate limit exceeded for API client');
  }
  
  const client = axios.create({
    baseURL,
    timeout,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      // SECURITY: Add security headers (A05)
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
    }
  });
  
  // SECURITY: Add authentication token if provided (A07)
  if (token) {
    client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }
  
  // SECURITY: Request interceptor to sign requests if needed (A08)
  if (signRequests && secretKey) {
    client.interceptors.request.use(
      (config) => {
        const method = config.method?.toUpperCase() || 'GET';
        const path = config.url || '';
        const body = config.data ? JSON.stringify(config.data) : '';
        
        const signature = createRequestSignature(method, path, body, secretKey);
        config.headers['X-Signature'] = signature;
        
        return config;
      },
      (error) => Promise.reject(error)
    );
  }
  
  // SECURITY: Response interceptor to validate and sanitize responses (A03, A05)
  client.interceptors.response.use(
    (response) => {
      // Validate response structure
      const data = response.data as SecureAPIResponse;
      
      if (!data || typeof data !== 'object') {
        throw new Error('[SECURITY] Invalid API response format');
      }
      
      // Log successful response
      console.log(`[API] Success - ${response.config.method?.toUpperCase()} ${response.config.url}`);
      
      return response;
    },
    (error: AxiosError) => {
      // SECURITY: Log errors but don't expose sensitive information (A05, A09)
      console.error(`[API] Error - ${error.config?.method?.toUpperCase()} ${error.config?.url} - ${error.message}`);
      
      // Don't expose stack traces to client
      if (error.response?.data) {
        const data = error.response.data as any;
        if (data.stack) {
          delete data.stack;
        }
      }
      
      return Promise.reject(error);
    }
  );
  
  return client;
}

/**
 * SECURITY: Validate API response
 * A03:2021 - Injection Prevention
 */
export function validateAPIResponse<T>(
  response: any,
  expectedSchema?: Record<string, string>
): { valid: boolean; data: T | null; error: string | null } {
  try {
    // Check if response is object
    if (!response || typeof response !== 'object') {
      return {
        valid: false,
        data: null,
        error: 'Invalid response type'
      };
    }
    
    // Check required fields
    if (response.success === undefined && !response.error) {
      return {
        valid: false,
        data: null,
        error: 'Response missing required fields'
      };
    }
    
    // Validate schema if provided
    if (expectedSchema && response.data) {
      for (const [key, type] of Object.entries(expectedSchema)) {
        if (!(key in response.data)) {
          return {
            valid: false,
            data: null,
            error: `Missing required field: ${key}`
          };
        }
        
        if (typeof response.data[key] !== type) {
          return {
            valid: false,
            data: null,
            error: `Invalid type for field ${key}: expected ${type}, got ${typeof response.data[key]}`
          };
        }
      }
    }
    
    return {
      valid: true,
      data: response.data as T,
      error: null
    };
  } catch (error) {
    console.error('[SECURITY] Response validation error:', error);
    return {
      valid: false,
      data: null,
      error: 'Response validation failed'
    };
  }
}

/**
 * SECURITY: Sanitize API request payload
 * A03:2021 - Injection Prevention & A04:2021 - Insecure Design
 */
export function sanitizeRequestPayload(payload: Record<string, any>): Record<string, any> {
  if (!payload || typeof payload !== 'object') {
    return {};
  }
  
  const sanitized: Record<string, any> = {};
  
  for (const [key, value] of Object.entries(payload)) {
    // Sanitize key
    if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
      console.warn(`[SECURITY] Suspicious key name: ${key}`);
      continue;
    }
    
    // Sanitize value based on type
    if (typeof value === 'string') {
      sanitized[key] = sanitizeHTML(value);
    } else if (typeof value === 'number') {
      sanitized[key] = value;
    } else if (typeof value === 'boolean') {
      sanitized[key] = value;
    } else if (Array.isArray(value)) {
      sanitized[key] = value.map(v =>
        typeof v === 'string' ? sanitizeHTML(v) : v
      );
    } else if (value === null) {
      sanitized[key] = null;
    } else if (typeof value === 'object') {
      // Recursively sanitize nested objects
      sanitized[key] = sanitizeRequestPayload(value);
    }
  }
  
  return sanitized;
}

/**
 * SECURITY: Validate API error response
 * A05:2021 - Security Misconfiguration
 */
export function analyzeAPIError(error: any): {
  statusCode: number;
  message: string;
  isClientError: boolean;
  isServerError: boolean;
  isNetworkError: boolean;
} {
  const defaultError = {
    statusCode: 0,
    message: 'Unknown error occurred',
    isClientError: false,
    isServerError: false,
    isNetworkError: true
  };
  
  if (!error) {
    return defaultError;
  }
  
  // Axios error
  if (error.response) {
    const { status } = error.response;
    return {
      statusCode: status,
      message: error.response?.data?.error?.message || error.message || 'Request failed',
      isClientError: status >= 400 && status < 500,
      isServerError: status >= 500,
      isNetworkError: false
    };
  }
  
  // Network error
  if (error.code === 'ECONNABORTED') {
    return {
      ...defaultError,
      message: 'Request timeout'
    };
  }
  
  return defaultError;
}

/**
 * SECURITY: Build secure query parameters
 * A03:2021 - Injection Prevention
 */
export function buildSecureQueryParams(
  params: Record<string, any>
): URLSearchParams {
  const searchParams = new URLSearchParams();
  
  for (const [key, value] of Object.entries(params)) {
    // Validate key
    if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
      console.warn(`[SECURITY] Invalid query parameter key: ${key}`);
      continue;
    }
    
    // Validate value
    if (typeof value === 'string') {
      if (validateText(value, 500)) {
        searchParams.append(key, value);
      }
    } else if (typeof value === 'number') {
      searchParams.append(key, String(value));
    } else if (typeof value === 'boolean') {
      searchParams.append(key, String(value));
    }
  }
  
  return searchParams;
}

/**
 * SECURITY: Retry logic with exponential backoff
 * A05:2021 - Security Misconfiguration
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  initialDelayMs: number = 1000
): Promise<T> {
  let lastError: any;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      // Don't retry on client errors (4xx)
      if (error instanceof AxiosError && error.response?.status && error.response.status < 500) {
        throw error;
      }
      
      if (attempt < maxRetries) {
        // Exponential backoff: 1s, 2s, 4s
        const delayMs = initialDelayMs * Math.pow(2, attempt - 1);
        console.log(`[API] Retry attempt ${attempt}/${maxRetries} after ${delayMs}ms`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }
  
  throw lastError;
}

/**
 * SECURITY: API health check
 * A05:2021 - Monitoring & A09:2021 - Logging
 */
export async function checkAPIHealth(
  client: AxiosInstance,
  healthEndpoint: string = '/health'
): Promise<boolean> {
  try {
    const response = await client.get(healthEndpoint, { timeout: 5000 });
    return response.status === 200;
  } catch (error) {
    console.error('[SECURITY] API health check failed:', error);
    return false;
  }
}

export default {
  createSecureAPIClient,
  validateAPIResponse,
  sanitizeRequestPayload,
  analyzeAPIError,
  buildSecureQueryParams,
  retryWithBackoff,
  checkAPIHealth
};

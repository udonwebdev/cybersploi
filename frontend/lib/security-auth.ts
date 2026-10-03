/**
 * SECURITY UTILITY - Authentication & Authorization
 * OWASP A01:2021 - Broken Access Control
 * OWASP A07:2021 - Identification and Authentication Failures
 */

import { cookies } from 'next/headers';

/**
 * SECURITY: Token structure for JWT validation
 */
export interface SecurityToken {
  userId: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer';
  permissions: string[];
  iat: number;
  exp: number;
  iss: string; // Issuer
}

/**
 * SECURITY: User context with role-based access
 */
export interface UserContext {
  userId: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer';
  permissions: string[];
  isAuthenticated: boolean;
}

/**
 * SECURITY: Default permissions based on role
 * A01:2021 - Broken Access Control (Role-based access control)
 */
const ROLE_PERMISSIONS: Record<string, string[]> = {
  admin: [
    'read:all',
    'write:all',
    'delete:all',
    'manage:users',
    'manage:settings',
    'view:audit_logs',
    'access:admin_panel',
    'manage:integrations',
    'manage:policies'
  ],
  operator: [
    'read:own',
    'write:own',
    'read:shared',
    'view:reports',
    'execute:scans',
    'view:incidents',
    'create:tickets',
    'view:audit_logs'
  ],
  viewer: [
    'read:own',
    'read:shared',
    'view:reports',
    'view:dashboards'
  ]
};

/**
 * SECURITY: Get authentication token from cookies
 * A07:2021 - Identification and Authentication Failures
 */
export async function getAuthToken(): Promise<string | null> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get('auth_token')?.value;
    return token || null;
  } catch {
    return null;
  }
}

/**
 * SECURITY: Validate token expiration
 * A07:2021 - Identification and Authentication Failures
 */
export function isTokenExpired(token: SecurityToken): boolean {
  const now = Math.floor(Date.now() / 1000);
  return token.exp < now;
}

/**
 * SECURITY: Check if user has specific permission
 * A01:2021 - Broken Access Control
 */
export function hasPermission(userContext: UserContext, requiredPermission: string): boolean {
  if (!userContext.isAuthenticated) {
    return false;
  }
  
  return userContext.permissions.includes(requiredPermission) ||
         userContext.permissions.includes('*'); // Wildcard for admin
}

/**
 * SECURITY: Check if user has any of the required permissions
 * A01:2021 - Broken Access Control
 */
export function hasAnyPermission(userContext: UserContext, permissions: string[]): boolean {
  if (!userContext.isAuthenticated) {
    return false;
  }
  
  return permissions.some(permission =>
    userContext.permissions.includes(permission) ||
    userContext.permissions.includes('*')
  );
}

/**
 * SECURITY: Check if user has all required permissions
 * A01:2021 - Broken Access Control
 */
export function hasAllPermissions(userContext: UserContext, permissions: string[]): boolean {
  if (!userContext.isAuthenticated) {
    return false;
  }
  
  return permissions.every(permission =>
    userContext.permissions.includes(permission) ||
    userContext.permissions.includes('*')
  );
}

/**
 * SECURITY: Generate permissions based on role
 * A01:2021 - Broken Access Control
 */
export function getPermissionsForRole(role: 'admin' | 'operator' | 'viewer'): string[] {
  return ROLE_PERMISSIONS[role] || [];
}

/**
 * SECURITY: Create user context from token
 * A01:2021 - Broken Access Control & A07:2021 - Authentication
 */
export function createUserContext(
  token: SecurityToken,
  isAuthenticated: boolean = true
): UserContext {
  return {
    userId: token.userId,
    email: token.email,
    role: token.role,
    permissions: token.permissions || getPermissionsForRole(token.role),
    isAuthenticated
  };
}

/**
 * SECURITY: Anonymous user context (for unauthenticated users)
 * A01:2021 - Broken Access Control
 */
export function getAnonymousContext(): UserContext {
  return {
    userId: '',
    email: '',
    role: 'viewer',
    permissions: ['read:public'],
    isAuthenticated: false
  };
}

/**
 * SECURITY: Validate token issuer
 * A07:2021 - Identification & Authentication Failures
 */
export function validateTokenIssuer(token: SecurityToken, expectedIssuer: string): boolean {
  return token.iss === expectedIssuer;
}

/**
 * SECURITY: Audit log entry for access control
 * A09:2021 - Logging & Monitoring Failures
 */
export interface AuditLog {
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  result: 'success' | 'failure';
  details?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * SECURITY: Create audit log entry
 * A09:2021 - Logging & Monitoring Failures
 */
export function createAuditLog(
  userId: string,
  action: string,
  resource: string,
  result: 'success' | 'failure' = 'success',
  details?: Record<string, any>,
  ipAddress?: string,
  userAgent?: string
): AuditLog {
  return {
    timestamp: new Date().toISOString(),
    userId,
    action,
    resource,
    result,
    details,
    ipAddress,
    userAgent
  };
}

/**
 * SECURITY: Log authentication attempt
 * A07:2021 - Authentication & A09:2021 - Logging & Monitoring
 */
export function logAuthenticationAttempt(
  email: string,
  result: 'success' | 'failed',
  ipAddress?: string
): void {
  console.log(`[AUTH] ${result.toUpperCase()} login attempt for ${email} from IP: ${ipAddress || 'unknown'}`);
}

/**
 * SECURITY: Log permission denial
 * A01:2021 - Access Control & A09:2021 - Logging & Monitoring
 */
export function logPermissionDenial(
  userId: string,
  requiredPermission: string,
  resource: string,
  ipAddress?: string
): void {
  console.log(`[ACCESS CONTROL] Permission denied - User: ${userId}, Permission: ${requiredPermission}, Resource: ${resource}, IP: ${ipAddress || 'unknown'}`);
}

/**
 * SECURITY: Session validation
 * A07:2021 - Identification & Authentication Failures
 */
export async function validateSession(): Promise<UserContext | null> {
  try {
    // In production, this would fetch and validate the token against a backend service
    const token = await getAuthToken();
    
    if (!token) {
      return null;
    }
    
    // Validate token format (JWT has 3 parts separated by dots)
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.log('[SECURITY] Invalid token format detected');
      return null;
    }
    
    // Note: Full JWT validation would be done server-side
    // Here we're just doing basic format validation
    
    return null; // In production, decode and validate token
  } catch (error) {
    console.error('[SECURITY] Session validation error:', error);
    return null;
  }
}

/**
 * SECURITY: Clear authentication
 * A07:2021 - Secure logout
 */
export async function clearAuthentication(): Promise<void> {
  try {
    const cookieStore = await cookies();
    cookieStore.delete('auth_token');
    cookieStore.delete('session_id');
  } catch (error) {
    console.error('[SECURITY] Error clearing authentication:', error);
  }
}

export default {
  getAuthToken,
  isTokenExpired,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getPermissionsForRole,
  createUserContext,
  getAnonymousContext,
  validateTokenIssuer,
  createAuditLog,
  logAuthenticationAttempt,
  logPermissionDenial,
  validateSession,
  clearAuthentication
};

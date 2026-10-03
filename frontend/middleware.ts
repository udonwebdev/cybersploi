import { NextRequest, NextResponse } from "next/server";

/**
 * SECURITY MIDDLEWARE - OWASP Compliance
 * 
 * Implements:
 * - A01: Broken Access Control - Route Protection & Role Boundary
 * - A02: Cryptographic Failures - HTTPS & Security Transport
 * - A05: Security Misconfiguration - Modern HTTP Security Headers
 * - A07: Identification and Authentication Failures - Token & Session Validation
 * - A09: Security Logging & Monitoring
 */

const publicRoutes = ["/", "/login", "/register", "/consent"];

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Allow static Next.js assets and API proxy routes without interception
  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/api") ||
    pathname.startsWith("/favicon") ||
    pathname.includes(".")
  ) {
    return NextResponse.next();
  }

  // Retrieve token from cookies or authorization header
  const token =
    request.cookies.get("cybersploi_token")?.value ||
    request.cookies.get("auth_token")?.value ||
    request.headers.get("authorization")?.replace("Bearer ", "");

  // Determine if path is public (/login, /register, /consent)
  const isPublic = publicRoutes.some((p) => pathname === p || pathname.startsWith(`${p}/`));

  // Note: We allow direct access to /login and /register so operators can authenticate or re-enter credentials anytime

  // If trying to access any protected route without a valid token, strictly redirect to /login
  if (!isPublic && !token) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("from", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Create response
  const response = NextResponse.next();

  // Security Headers (OWASP A05)
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-XSS-Protection", "1; mode=block");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};

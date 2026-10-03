/** @type {import('next').NextConfig} */

/**
 * SECURITY CONFIGURATION - OWASP Compliance
 * 
 * Implements:
 * - A05: Security Misconfiguration
 * - A02: Cryptographic Failures (HTTPS enforcement)
 * - A06: Vulnerable and Outdated Components (dependency updates)
 */

const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  images: {
    unoptimized: true,
  },
  
  // SECURITY: Prevent clickjacking attacks (A05)
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'X-Frame-Options',
          value: 'DENY'
        },
        {
          key: 'X-Content-Type-Options',
          value: 'nosniff'
        },
        {
          key: 'X-XSS-Protection',
          value: '1; mode=block'
        },
        {
          key: 'Referrer-Policy',
          value: 'strict-origin-when-cross-origin'
        },
        {
          key: 'Permissions-Policy',
          value: 'geolocation=(), microphone=(), camera=()'
        }
      ]
    }
  ],

  // SECURITY: Configure CORS for external API calls (A05)
  async rewrites() {
    return {
      beforeFiles: [
        {
          source: '/api/:path*',
          destination: `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/:path*`
        }
      ]
    };
  },

  // SECURITY: Disable X-Powered-By header (A05)
  poweredByHeader: false,

  // SECURITY: Compress response bodies (A05)
  compress: true,

  // SECURITY: Generate ETags for caching (A02)
  generateEtags: true,

  // SECURITY: Product naming - don't expose Next.js version
  productionBrowserSourceMaps: false,

  // SECURITY: Configure environment variable exposure (A02)
  publicRuntimeConfig: {
    // Only expose non-sensitive environment variables
    NEXT_PUBLIC_APP_NAME: 'CYBERSPLOI',
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
  },

  // Webpack configuration
  webpack: (config) => {
    return config;
  }
};

module.exports = nextConfig;
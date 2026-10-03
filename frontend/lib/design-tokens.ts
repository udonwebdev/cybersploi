/**
 * Design Tokens System
 * Centralized design language for CYBERSPLOI
 * Based on modern 2024/2025 cybersecurity UI patterns
 */

export const DESIGN_TOKENS = {
  // ═══════════════════════════════════════════════════════════
  // COLOR PALETTE - Enhanced for Modern Dark UI
  // ═══════════════════════════════════════════════════════════
  colors: {
    // Primary - Cyan Accent
    primary: {
      50: '#f0feff',
      100: '#e0fdff',
      200: '#b3fbff',
      300: '#7ef8ff',
      400: '#39f3ff',
      500: '#1be9ff', // Primary action color
      600: '#00dff0',
      700: '#00c7d9',
      800: '#00a3b0',
      900: '#008d99',
    },

    // Secondary - Purple/Blue Accent
    secondary: {
      400: '#b59aff',
      500: '#a389ff', // Secondary actions
      600: '#9175ff',
    },

    // Backgrounds
    background: {
      primary: '#0f0f13', // Main background
      secondary: '#1a1a23', // Slightly elevated
      tertiary: '#24242f', // Cards, surfaces
    },

    // Surfaces
    surface: {
      base: '#16161e', // Default surface
      hover: '#1f1f2e', // Hovered surface
      active: '#2a2a3f', // Active/selected surface
      overlay: 'rgba(22, 22, 30, 0.8)', // Semi-transparent overlay
    },

    // Semantic Colors
    success: '#4ade80',
    warning: '#facc15',
    error: '#ff5757',
    critical: '#ff3333',
    info: '#60a5fa',

    // Severity Levels
    severity: {
      critical: { bg: '#ff3333', text: '#ffe6e6' },
      high: { bg: '#ff6b35', text: '#ffe8db' },
      medium: { bg: '#ffa500', text: '#fff4e6' },
      low: { bg: '#3b82f6', text: '#dbeafe' },
      info: { bg: '#06b6d4', text: '#cffafe' },
    },

    // Grayscale
    gray: {
      50: '#f9fafb',
      100: '#f3f4f6',
      200: '#e5e7eb',
      300: '#d1d5db',
      400: '#9ca3af',
      500: '#6b7280',
      600: '#4b5563',
      700: '#374151',
      800: '#1f2937',
      900: '#111827',
    },

    // Neutral (for text and borders)
    neutral: {
      white: '#ffffff',
      text: {
        primary: '#f5f5f7',
        secondary: '#b3b3b8',
        tertiary: '#808089',
        disabled: '#4f4f5a',
      },
      border: {
        light: 'rgba(255, 255, 255, 0.1)',
        default: 'rgba(255, 255, 255, 0.15)',
        strong: 'rgba(255, 255, 255, 0.2)',
      },
    },
  },

  // ═══════════════════════════════════════════════════════════
  // TYPOGRAPHY
  // ═══════════════════════════════════════════════════════════
  typography: {
    // Font Families
    families: {
      display: "'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif",
      body: "'Manrope', -apple-system, BlinkMacSystemFont, sans-serif",
      mono: "'IBM Plex Mono', monospace",
    },

    // Heading Scales
    heading: {
      h1: {
        size: '3.5rem', // 56px
        weight: 800,
        lineHeight: 1.1,
        letterSpacing: '-0.02em',
      },
      h2: {
        size: '2.25rem', // 36px
        weight: 700,
        lineHeight: 1.2,
        letterSpacing: '-0.01em',
      },
      h3: {
        size: '1.5rem', // 24px
        weight: 700,
        lineHeight: 1.3,
        letterSpacing: '-0.005em',
      },
      h4: {
        size: '1.25rem', // 20px
        weight: 600,
        lineHeight: 1.4,
      },
      h5: {
        size: '1rem', // 16px
        weight: 600,
        lineHeight: 1.5,
      },
    },

    // Body Text
    body: {
      lg: {
        size: '1.125rem', // 18px
        weight: 400,
        lineHeight: 1.6,
      },
      base: {
        size: '1rem', // 16px
        weight: 400,
        lineHeight: 1.6,
      },
      sm: {
        size: '0.875rem', // 14px
        weight: 400,
        lineHeight: 1.5,
      },
      xs: {
        size: '0.75rem', // 12px
        weight: 500,
        lineHeight: 1.5,
        letterSpacing: '0.02em',
      },
    },

    // Labels & Captions
    label: {
      lg: {
        size: '0.875rem', // 14px
        weight: 600,
        letterSpacing: '0.01em',
      },
      sm: {
        size: '0.75rem', // 12px
        weight: 600,
        letterSpacing: '0.015em',
        textTransform: 'uppercase',
      },
    },
  },

  // ═══════════════════════════════════════════════════════════
  // SPACING SYSTEM (8px base)
  // ═══════════════════════════════════════════════════════════
  spacing: {
    0: '0',
    1: '0.25rem', // 4px
    2: '0.5rem', // 8px
    3: '0.75rem', // 12px
    4: '1rem', // 16px
    5: '1.25rem', // 20px
    6: '1.5rem', // 24px
    8: '2rem', // 32px
    10: '2.5rem', // 40px
    12: '3rem', // 48px
    16: '4rem', // 64px
    20: '5rem', // 80px
    24: '6rem', // 96px
  },

  // ═══════════════════════════════════════════════════════════
  // BORDER RADIUS (Modern, Rounded)
  // ═══════════════════════════════════════════════════════════
  radius: {
    none: '0',
    xs: '0.25rem', // 4px - subtle
    sm: '0.5rem', // 8px - buttons, small elements
    md: '0.75rem', // 12px - cards, default
    lg: '1rem', // 16px - modals, large elements
    xl: '1.5rem', // 24px - hero sections
    full: '9999px', // Fully rounded (pills)
  },

  // ═══════════════════════════════════════════════════════════
  // SHADOWS (Glassmorphism & Depth)
  // ═══════════════════════════════════════════════════════════
  shadows: {
    none: 'none',
    xs: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    sm: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
    glow: '0 0 20px rgba(27, 233, 255, 0.3)',
    glowStrong: '0 0 30px rgba(27, 233, 255, 0.5)',
  },

  // ═══════════════════════════════════════════════════════════
  // TRANSITIONS & ANIMATIONS
  // ═══════════════════════════════════════════════════════════
  transitions: {
    fast: '150ms cubic-bezier(0.4, 0, 0.2, 1)',
    base: '200ms cubic-bezier(0.4, 0, 0.2, 1)',
    slow: '300ms cubic-bezier(0.4, 0, 0.2, 1)',
    slower: '500ms cubic-bezier(0.4, 0, 0.2, 1)',
  },

  // ═══════════════════════════════════════════════════════════
  // COMPONENTS - Pre-built Component Styles
  // ═══════════════════════════════════════════════════════════
  components: {
    // Button Sizes
    button: {
      sizes: {
        xs: { padding: '0.5rem 1rem', fontSize: '0.75rem', height: '2rem' },
        sm: { padding: '0.625rem 1.25rem', fontSize: '0.875rem', height: '2.25rem' },
        md: { padding: '0.75rem 1.5rem', fontSize: '1rem', height: '2.5rem' },
        lg: { padding: '1rem 2rem', fontSize: '1rem', height: '3rem' },
        xl: { padding: '1.25rem 2.5rem', fontSize: '1.125rem', height: '3.5rem' },
      },
      variants: {
        primary: {
          bg: '#1be9ff',
          text: '#000000',
          hover: 'brightness(110%)',
          active: 'brightness(95%)',
        },
        secondary: {
          bg: 'rgba(255, 255, 255, 0.1)',
          text: '#f5f5f7',
          hover: 'rgba(255, 255, 255, 0.15)',
          border: '1px solid rgba(255, 255, 255, 0.2)',
        },
        danger: {
          bg: '#ff5757',
          text: '#ffffff',
          hover: 'brightness(110%)',
        },
        ghost: {
          bg: 'transparent',
          text: '#1be9ff',
          hover: 'rgba(27, 233, 255, 0.1)',
        },
      },
    },

    // Input Field Styling
    input: {
      base: {
        bg: 'rgba(255, 255, 255, 0.05)',
        border: '1px solid rgba(255, 255, 255, 0.15)',
        focusBorder: '1px solid #1be9ff',
        text: '#f5f5f7',
        placeholder: '#808089',
        radius: '0.75rem',
        padding: '0.75rem 1rem',
      },
    },

    // Card Styling
    card: {
      base: {
        bg: 'rgba(22, 22, 30, 0.6)',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        backdrop: 'blur(10px)',
        radius: '1rem',
        padding: '1.5rem',
        shadow: '0 8px 32px rgba(0, 0, 0, 0.1)',
      },
    },

    // Badge/Pill Styling
    badge: {
      radius: '9999px',
      padding: '0.375rem 0.75rem',
      fontSize: '0.75rem',
      fontWeight: 600,
    },
  },

  // ═══════════════════════════════════════════════════════════
  // BREAKPOINTS (Tailwind-aligned)
  // ═══════════════════════════════════════════════════════════
  breakpoints: {
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
  },

  // ═══════════════════════════════════════════════════════════
  // Z-INDEX STACKING CONTEXT
  // ═══════════════════════════════════════════════════════════
  zIndex: {
    hide: -1,
    auto: 'auto',
    base: 0,
    dropdown: 10,
    sticky: 20,
    fixed: 30,
    modalBackdrop: 40,
    modal: 50,
    popover: 60,
    tooltip: 70,
    notification: 80,
  },

  // ═══════════════════════════════════════════════════════════
  // GRADIENTS - Modern Accents
  // ═══════════════════════════════════════════════════════════
  gradients: {
    cyanToBlue:
      'linear-gradient(135deg, #1be9ff 0%, #a389ff 100%)',
    purpleToBlue:
      'linear-gradient(135deg, #a389ff 0%, #60a5fa 100%)',
    redToOrange:
      'linear-gradient(135deg, #ff5757 0%, #ff6b35 100%)',
    greenToTeal:
      'linear-gradient(135deg, #4ade80 0%, #06b6d4 100%)',
    darkOverlay:
      'radial-gradient(circle at top right, rgba(27, 233, 255, 0.1), transparent)',
  },
} as const;

// Utility function to get color by severity
export const getSeverityColor = (severity: 'critical' | 'high' | 'medium' | 'low' | 'info') => {
  return DESIGN_TOKENS.colors.severity[severity];
};

// Utility function for responsive values
export const responsive = {
  mobile: DESIGN_TOKENS.breakpoints.sm,
  tablet: DESIGN_TOKENS.breakpoints.md,
  desktop: DESIGN_TOKENS.breakpoints.lg,
} as const;

export default DESIGN_TOKENS;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:      '#020817',
          surface: '#060f1e',
          card:    '#0a1628',
          panel:   '#0d1f3c',
          border:  '#1e3a5f',
          cyan:    '#00f5ff',
          purple:  '#8b5cf6',
          green:   '#00ff88',
          red:     '#ff3366',
          orange:  '#ff8c00',
          yellow:  '#ffd700',
          text:    '#e2e8f0',
          muted:   '#64748b',
          dim:     '#334155',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan':   '0 0 20px rgba(0,245,255,0.4), 0 0 60px rgba(0,245,255,0.12)',
        'glow-purple': '0 0 20px rgba(139,92,246,0.4), 0 0 60px rgba(139,92,246,0.12)',
        'glow-green':  '0 0 20px rgba(0,255,136,0.4), 0 0 60px rgba(0,255,136,0.12)',
        'glow-red':    '0 0 20px rgba(255,51,102,0.4), 0 0 60px rgba(255,51,102,0.12)',
        'glow-yellow': '0 0 20px rgba(255,215,0,0.4),  0 0 60px rgba(255,215,0,0.12)',
        'glow-sm':     '0 0 10px rgba(0,245,255,0.25)',
        'inner-glow':  'inset 0 0 30px rgba(0,245,255,0.05)',
      },
      backgroundImage: {
        'cyber-grid':     "linear-gradient(rgba(0,245,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,245,255,0.025) 1px, transparent 1px)",
        'gradient-cyber': 'linear-gradient(135deg, #020817 0%, #060f1e 50%, #0a1628 100%)',
        'gradient-neon':  'linear-gradient(135deg, #00f5ff, #8b5cf6)',
        'gradient-danger':'linear-gradient(135deg, #ff3366, #ff8c00)',
        'gradient-safe':  'linear-gradient(135deg, #00ff88, #00f5ff)',
      },
      backgroundSize: {
        'grid': '60px 60px',
      },
      animation: {
        'pulse-slow':    'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'pulse-fast':    'pulse 0.8s ease-in-out infinite',
        'glow-pulse':    'glowPulse 2s ease-in-out infinite',
        'scan':          'scan 2s linear infinite',
        'float':         'float 6s ease-in-out infinite',
        'fadeInUp':      'fadeInUp 0.5s ease-out',
        'blink':         'blink 1s step-end infinite',
        'spin-slow':     'spin 3s linear infinite',
        'shimmer':       'shimmer 2s linear infinite',
        'slide-in-left': 'slideInLeft 0.4s ease-out',
        'slide-in-right':'slideInRight 0.4s ease-out',
        'zoom-in':       'zoomIn 0.3s ease-out',
        'typing':        'typing 2s steps(40) forwards',
      },
      keyframes: {
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 5px rgba(0,245,255,0.3)' },
          '50%':      { boxShadow: '0 0 30px rgba(0,245,255,0.9), 0 0 60px rgba(0,245,255,0.3)' },
        },
        scan: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%':      { transform: 'translateY(-8px)' },
        },
        fadeInUp: {
          '0%':   { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0' },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        slideInLeft: {
          '0%':   { opacity: '0', transform: 'translateX(-20px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        slideInRight: {
          '0%':   { opacity: '0', transform: 'translateX(20px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        zoomIn: {
          '0%':   { opacity: '0', transform: 'scale(0.9)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        typing: {
          '0%':   { width: '0' },
          '100%': { width: '100%' },
        },
      },
      borderRadius: {
        'xl': '12px',
        '2xl': '16px',
        '3xl': '24px',
      },
      spacing: {
        '18': '4.5rem',
        '22': '5.5rem',
      },
    },
  },
  plugins: [],
}

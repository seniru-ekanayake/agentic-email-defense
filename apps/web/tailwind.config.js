/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        sidebar: "var(--sidebar)",
        card: "var(--card)",
        border: "var(--border)",
        neon: {
          cyan: "#00e5ff",
          rose: "#ff0055",
          amber: "#ffaa00",
          emerald: "#00ff88",
          purple: "#b026ff",
          blue: "#387aff",
        }
      },
      fontFamily: {
        poppins: ['Poppins', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -2px rgba(0, 229, 255, 0.4)',
        'glow-rose': '0 0 20px -2px rgba(255, 0, 85, 0.4)',
        'glow-amber': '0 0 20px -2px rgba(255, 170, 0, 0.4)',
        'glow-emerald': '0 0 20px -2px rgba(0, 255, 136, 0.4)',
        'tactical-card': '0 4px 24px -1px rgba(0, 0, 0, 0.6), inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
      }
    },
  },
  plugins: [],
};

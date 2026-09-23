/** @type {import('tailwindcss').Config} */
module.exports = {
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
        surface: "#0f172a",
        border: "#1e293b",
        primary: "#38bdf8",
        danger: "#ef4444",
        warning: "#f59e0b",
        success: "#10b981"
      },
    },
  },
  plugins: [],
};

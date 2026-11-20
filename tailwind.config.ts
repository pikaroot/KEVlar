import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // "Quiet terminal" theme, shared with pikaroot.github.io: the zinc scale
      // becomes graphite and indigo becomes the one phosphor-green accent, so
      // every existing utility class picks the new palette up unchanged.
      colors: {
        zinc: {
          50: "#f5f4f1",
          100: "#e7e5e0",
          200: "#d6d4cf",
          300: "#bfc2be",
          400: "#949995",
          500: "#6c716e",
          600: "#4d524f",
          700: "#363b39",
          800: "#262a28",
          900: "#191c1b",
          950: "#0c0d0d",
        },
        indigo: {
          50: "#effbf4",
          100: "#d8f5e4",
          200: "#b3ebcb",
          300: "#8ddbb0",
          400: "#76d19f",
          500: "#5fc98f",
          600: "#48b87b",
          700: "#349763",
          800: "#2a7650",
          900: "#215c3f",
          950: "#123523",
        },
      },
      borderRadius: {
        DEFAULT: "3px",
        md: "4px",
        lg: "5px",
        xl: "6px",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains-mono)", "ui-monospace", "monospace"],
      },
      keyframes: {
        "kev-pulse": {
          "0%, 100%": { opacity: "1", boxShadow: "0 0 0 0 rgba(225, 29, 72, 0.5)" },
          "50%": { opacity: "0.85", boxShadow: "0 0 0 6px rgba(225, 29, 72, 0)" },
        },
        "fade-in": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "toast-in": {
          "0%": { opacity: "0", transform: "translateY(12px) scale(0.98)" },
          "100%": { opacity: "1", transform: "translateY(0) scale(1)" },
        },
      },
      animation: {
        "kev-pulse": "kev-pulse 1.8s ease-in-out infinite",
        "fade-in": "fade-in 0.35s ease-out",
        "toast-in": "toast-in 0.25s ease-out",
      },
    },
  },
  plugins: [],
};

export default config;

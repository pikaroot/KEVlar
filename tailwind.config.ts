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

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: { 0: "#0f1012", 1: "#1a1a19", 2: "#232321", 3: "#2e2e2b" },
        ink: { primary: "#f0efec", secondary: "#c3c2b7", muted: "#8f8e86" },
        accent: "#3987e5",
        status: { good: "#0ca30c", warning: "#fab219", serious: "#ec835a", critical: "#d03b3b" },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};

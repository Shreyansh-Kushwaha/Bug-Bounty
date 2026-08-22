/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    container: {
      center: true,
      padding: "1.5rem",
      screens: {
        sm: "640px",
        md: "768px",
        lg: "1024px",
        xl: "1180px",
      },
    },
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "system-ui",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SF Mono",
          "JetBrains Mono",
          "Menlo",
          "Consolas",
          "monospace",
        ],
        script: ["Caveat", "cursive"],
      },
      animation: {
        float: "orb-float 20s ease-in-out infinite",
        "float-slow": "orb-float 28s ease-in-out infinite",
        "float-slower": "orb-float 34s ease-in-out infinite",
        blink: "caret-blink 1s steps(1) infinite",
        "fade-up": "fade-up 0.6s ease-out both",
      },
      keyframes: {
        "orb-float": {
          "0%,100%": { transform: "translate(0,0) scale(1)" },
          "33%":     { transform: "translate(60px,-40px) scale(1.1)" },
          "66%":     { transform: "translate(-50px,50px) scale(0.92)" },
        },
        "caret-blink": {
          "0%,50%": { opacity: "1" },
          "51%,100%": { opacity: "0" },
        },
        "fade-up": {
          "0%":   { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      colors: {
        bg:           "var(--bg)",
        "bg-elev":    "var(--bg-elev)",
        "bg-card":    "var(--bg-card)",
        "bg-soft":    "var(--bg-soft)",
        fg:           "var(--fg)",
        "fg-muted":   "var(--fg-muted)",
        "fg-dim":     "var(--fg-dim)",
        accent:       "var(--accent)",
        "accent-hover": "var(--accent-hover)",
        "accent-soft":  "var(--accent-soft)",
        "accent-fg":    "var(--accent-fg)",
        ok:           "var(--ok)",
        "ok-soft":    "var(--ok-soft)",
        warn:         "var(--warn)",
        "warn-soft":  "var(--warn-soft)",
        bad:          "var(--bad)",
        "bad-soft":   "var(--bad-soft)",
        border:       "var(--border)",
        "border-strong": "var(--border-strong)",
      },
      borderRadius: {
        card: "12px",
      },
      boxShadow: {
        soft: "0 1px 2px rgba(15,23,42,.04), 0 1px 3px rgba(15,23,42,.06)",
        pop:  "0 12px 32px rgba(15,23,42,.08), 0 4px 8px rgba(15,23,42,.04)",
      },
      maxWidth: {
        site: "1180px",
      },
    },
  },
  plugins: [],
};

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        obsidian: "#F4F7F4",
        surface: "#FFFFFF",
        elevated: "#F1F5F1",
        panel: "#F7F9F7",
        border: "#E1E8E2",
        "border-subtle": "#EAF0EB",
        ink: "#18251D",
        "ink-secondary": "#506157",
        "ink-muted": "#76847A",
        lime: "#1D6848",
        "lime-dim": "#438360",
        "lime-glow": "rgba(29,104,72,0.10)",
        emerald: "#267A55",
        "emerald-dim": "rgba(38,122,85,0.12)",
        amber: "#9A6218",
        "amber-dim": "rgba(154,98,24,0.12)",
        ruby: "#B84343",
        "ruby-dim": "rgba(184,67,67,0.12)",
        sapphire: "#42677C",
        "sapphire-dim": "rgba(66,103,124,0.12)",
        forest: "#267A55",
        muted: "#506157",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        "2xs": ["0.625rem", { lineHeight: "0.875rem" }],
      },
      boxShadow: {
        panel: "0 2px 8px rgba(27,55,35,0.04)",
        "panel-hover": "0 8px 24px rgba(27,55,35,0.09)",
        "lime-sm": "0 0 0 1px rgba(29,104,72,0.22)",
        lime: "0 0 10px rgba(29,104,72,0.10)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4,0,0.6,1) infinite",
        "fade-in": "fadeIn 0.2s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

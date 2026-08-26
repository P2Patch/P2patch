/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Diagnostic-instrument palette. Deep cool slate, not hacker-black;
        // iris accent kept distinct from the green/amber/red status lamps.
        ink: "#0E1116",
        panel: "#151A21",
        elevated: "#1B222B",
        hairline: "#232B36",
        "hairline-strong": "#2E3846",
        ink2: "#0A0D11",
        txt: "#E6EAF0",
        "txt-dim": "#8B95A5",
        "txt-faint": "#5C6675",
        iris: "#8C7CF5",
        "iris-dim": "#6F5FD8",
        pass: "#4FB477",
        fail: "#E5615C",
        warn: "#E0A64E",
        info: "#5B9BD5",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.02) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        lamp: "0 0 0 3px rgba(0,0,0,0.35)",
      },
      keyframes: {
        pulse2: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
      },
      animation: {
        pulse2: "pulse2 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

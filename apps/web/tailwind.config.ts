import type { Config } from "tailwindcss";

export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "../../packages/ui/src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#05090D", surface: "#091117", card: "#0B151C", border: "#17262F",
        primary: "#31F27C", cyan: "#20D9FF", critical: "#FF404D", high: "#FF851B",
        medium: "#F4CA24", foreground: "#F2F7F9", muted: "#8FA4AE",
      },
      boxShadow: { panel: "0 12px 36px rgba(0,0,0,.18)" },
    },
  },
  plugins: [],
} satisfies Config;

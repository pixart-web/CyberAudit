import type { Config } from "tailwindcss";

export default {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "../../packages/ui/src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#080D13",
        surface: "#101922",
        card: "#101922",
        border: "#273B43",
        primary: "#8FE6CC",
        cyan: "#8FE6CC",
        critical: "#FF887E",
        high: "#F2BD74",
        medium: "#F2BD74",
        foreground: "#F0F5F6",
        muted: "#8299A1",
      },
      borderRadius: {
        sm: "4px",
        DEFAULT: "6px",
        md: "6px",
        lg: "8px",
        xl: "8px",
      },
      boxShadow: { panel: "0 16px 44px rgba(2,7,10,.28)" },
    },
  },
  plugins: [],
} satisfies Config;

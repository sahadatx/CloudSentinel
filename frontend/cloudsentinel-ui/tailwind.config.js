/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#0B0F14",
        surface: "#111820",
        card: "#151D26",
        line: "#26313D",
        text: "#F3F4F6",
        secondary: "#9CA3AF",
        muted: "#667085",
        critical: "#F04438",
        high: "#F79009",
        medium: "#FEC84B",
        success: "#12B76A",
      },
    },
  },
  plugins: [],
};

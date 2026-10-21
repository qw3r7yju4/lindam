module.exports = {
  content: [
    "./public/**/*.{html,js}",
    "./worker.js",
    "./src/**/*.{html,js,ts}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        serif: ["Playfair Display", "Georgia", "serif"],
      },
      colors: {
        sage: {
          50: "#f4f7f4",
          100: "#e4ebe4",
          200: "#c9d8c9",
          300: "#a3bca4",
          400: "#769a78",
          500: "#557c58",
          600: "#416244",
          700: "#354f37",
          800: "#2c402e",
          900: "#253527",
        },
        sand: {
          50: "#fdfcfa",
          100: "#f8f5ef",
          200: "#f0eadd",
          300: "#e4d9c5",
          400: "#d3c1a3",
          500: "#bca683",
        },
        clay: {
          50: "#fbf6f4",
          100: "#f6ebe5",
          200: "#eed5c8",
          300: "#e1b6a2",
          400: "#cf8f74",
          500: "#b87d64",
          600: "#a0664e",
          700: "#85513d",
        },
      },
      boxShadow: {
        soft: "0 4px 20px -2px rgba(44, 64, 46, 0.06), 0 2px 6px -1px rgba(44, 64, 46, 0.04)",
        elevated: "0 12px 32px -4px rgba(44, 64, 46, 0.10), 0 4px 12px -2px rgba(44, 64, 46, 0.06)",
        card: "0 1px 3px rgba(44, 64, 46, 0.05), 0 10px 24px -4px rgba(44, 64, 46, 0.08)",
      },
      animation: {
        "pulse-subtle": "pulseSubtle 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "float-gentle": "floatGentle 6s ease-in-out infinite",
        "breathe": "breathe 8s ease-in-out infinite",
      },
      keyframes: {
        pulseSubtle: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.7" },
        },
        floatGentle: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-6px)" },
        },
        breathe: {
          "0%, 100%": { transform: "scale(1)", opacity: "0.7" },
          "50%": { transform: "scale(1.3)", opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};


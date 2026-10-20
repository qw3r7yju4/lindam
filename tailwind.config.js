module.exports = {
  content: [
    "./public/**/*.{html,js}",
    "./worker.js",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        serif: ["Playfair Display", "serif"],
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
        },
        clay: {
          500: "#b87d64",
          600: "#a0664e",
        },
      },
    },
  },
  plugins: [],
};

import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        serif: ["Cormorant Garamond", "serif"],
        sans: ["Jost", "sans-serif"],
      },
      colors: {
        bg: "#FDF6F0",
        surface: "#FFFFFF",
        surface2: "#FAF0F4",
        border: "#EDD5DC",
        ink: "#3D2030",
        muted: "#B08090",
        accent: "#C4748A",
        accent2: "#E8A0B0",
        blush: "#F5DCE4",
      },
    },
  },
  plugins: [],
};
export default config;

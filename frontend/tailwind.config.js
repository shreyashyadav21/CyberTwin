/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        twin: {
          bg: '#F5F7F6',          // Primary background
          card: '#FFFFFF',        // Secondary background
          darknav: '#202E39',     // Dark navigation / sidebar
          primary: '#397C78',     // Primary accent (Teal)
          secondary: '#80AAA1',   // Secondary accent (Sage/Muted teal)
          text: '#253443',        // Primary text
          muted: '#718096',       // Secondary text
          border: '#E2E8F0',      // Soft border
          borderLight: '#EDF2F7', // Lighter border
          success: '#5B9678',     // Muted green success
          warning: '#D5A45C',     // Warm amber warning
          danger: '#CE7373',      // Muted red danger
        }
      },
      fontFamily: {
        sans: ['Inter', 'Manrope', 'system-ui', '-apple-system', 'sans-serif'],
      }
    },
  },
  plugins: [],
}


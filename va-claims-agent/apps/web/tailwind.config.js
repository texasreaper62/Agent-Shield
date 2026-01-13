/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        va: {
          blue: '#003e73',
          'blue-light': '#0071bc',
          gold: '#fdb81e',
          red: '#cd2026',
          gray: {
            100: '#f0f0f0',
            200: '#d6d7d9',
            300: '#aeb0b5',
            400: '#757575',
            500: '#5b616b',
            600: '#323a45',
          }
        }
      },
      fontFamily: {
        sans: ['Source Sans Pro', 'Helvetica Neue', 'Helvetica', 'Arial', 'sans-serif'],
      }
    },
  },
  plugins: [],
}

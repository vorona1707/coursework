/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./static/**/*.{html,js,tmpl}", 
    "./templates/**/*.{html,tmpl}"
  ],
  theme: {
    extend: {
      colors: {
        'button-color': '#7eb593',
      },
    },
  },
  plugins: [],
}


/**
 * Tailwind v4 runs as a single PostCSS plugin -- no `tailwind.config.js`,
 * no `autoprefixer` entry. Theme configuration lives in CSS (`@theme inline`
 * in `src/app/globals.css`), which is what lets the Tailwind token layer and
 * this project's pre-existing custom-property design system share one source
 * of truth instead of drifting as two parallel scales.
 */
const config = {
  plugins: {
    '@tailwindcss/postcss': {},
  },
};

export default config;

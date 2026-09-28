import { defineConfig } from 'knip/config';

export default defineConfig({
  tags: ['-lintignore'],
  ignoreDependencies: [
    'i18n-auto-translation',
    '@rjsf/validator-ajv8',
    // Imported from src/static/css/index.css, which knip does not scan.
    '@fontsource/geologica',
    '@fontsource/ibm-plex-sans',
    '@fontsource/roboto',
    'tippy.js',
    // Must stay the copy react-pdf resolves: pdf.js throws when the worker and the API
    // differ in version. Declaring it would let the two drift apart.
    'pdfjs-dist',
  ],
});

const ignorePatterns = [
  'extract-files',
  '@babel',
  '@mui',
  'react-leaflet',
  '@react-leaflet',
  'axios',
  'internmap',
  'd3-.+'
].join('|');

module.exports = {
  testEnvironment: 'jsdom',
  roots: ["./src"],
  testTimeout: 1200000,
  testRegex: ['src/.*\\.test\\.(jsx|tsx)$', 'tests/.*-test\\.(jsx|tsx)$'],
  transform: {
    "\\.(js|jsx|mjs|cjs|ts|tsx)$": "<rootDir>/jest/jest.relay.transform.js",
    "^(?!.*\\.(js|jsx|mjs|cjs|ts|tsx|css|json)$)": "<rootDir>/jest/jest.file.transform.js"
  },
  transformIgnorePatterns: ['node_modules/(?!' + ignorePatterns + ')'],
  collectCoverageFrom: ["src/**/*.{js,jsx,ts,tsx}", "!src/**/*.graphql.{js,jsx,ts,tsx}", "!src/**/*.d.ts"],
};

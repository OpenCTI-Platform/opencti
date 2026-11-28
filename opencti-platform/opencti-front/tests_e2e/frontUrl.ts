// Set E2E_FRONT_URL to test an already served front (e.g. the built one the platform serves itself)
// instead of starting the Vite dev server. Empty counts as unset, like for `webServer`.
export const FRONT_URL = process.env.E2E_FRONT_URL || 'http://localhost:3000';

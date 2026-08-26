export default {
  testDir: '.',
  testMatch: /\.spec\.mjs$/,
  timeout: 30000,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4300', viewport: { width: 1280, height: 800 } },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
};

import { defineConfig, devices } from '@playwright/test';
import teamsWebhook from './tests_e2e/webhooks/teams-webhook.js';
// https://playwright.dev/docs/browsers

/**
 * Read environment variables from file.
 * https://github.com/motdotla/dotenv
 */
// require('dotenv').config();

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
  testDir: './tests_e2e',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  retries: 0,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : '25%',
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [
    ['list'],
    ['monocart-reporter', {
      name: `OpenCTI Report`,
      outputFile: './test-results/report.html',
      // global coverage report options
      coverage: {
        entryFilter: (entry) => true,
        sourceFilter: (sourcePath) => sourcePath.startsWith('src'),
      },
      onEnd: async (reportData) => {
        // teams integration with webhook
        await teamsWebhook(reportData);
      }
    }]
  ],
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: 'http://localhost:3000',

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',
    screenshot: "only-on-failure",
    ignoreHTTPSErrors: true,
  },
  expect: { timeout: 60000 },
  timeout: 200000,
  /* Configure projects for major browsers */
  projects: [
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/
    },
    {
      name: 'init data',
      testMatch: "init.data.ts",
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'tests_e2e/.setup/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'tests_e2e/.setup/.auth/user.json',
        viewport: {
          width: 1920,
          height: 1080
        }
      },
      dependencies: ['init data'],
    },
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },
    //
    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari']}
    // }

    /* Test against mobile viewports. */
    // {
    //   name: 'Mobile Chrome',
    //   use: { ...devices['Pixel 5'] },
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: { ...devices['iPhone 12'] },
    // },

    /* Test against branded browsers. */
    // {
    //   name: 'Microsoft Edge',
    //   use: { ...devices['Desktop Edge'], channel: 'msedge' },
    // },
    // {
    //   name: 'Google Chrome',
    //   use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    // },
  ],

  /* Run your local dev server before starting the tests */
   webServer: {
     command: 'yarn start',
     url: 'http://localhost:3000',
     reuseExistingServer: true,
   },

});

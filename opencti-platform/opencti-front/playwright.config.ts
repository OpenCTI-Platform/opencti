import { defineConfig, devices } from '@playwright/test';

const BASE_PATH = process.env.APP__BASE_PATH ?? '';
const BASE_URL = `http://localhost:3000${BASE_PATH}`;

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
  fullyParallel: false,
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
    }]
  ],
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: BASE_URL,

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    ignoreHTTPSErrors: true,
  },
  expect: { timeout: 60000 },
  timeout: 200000,
  /* Configure projects for major browsers */
  projects: [
    {
      name: 'setup',
      testMatch: "**/*.setup.ts"
    },
    {
      name: 'init data',
      testMatch: "dataForTesting/init.data.ts",
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'tests_e2e/.setup/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'workflow setup',
      testMatch: "workflow/threatAdvisoryWorkflowSetup.spec.ts",
      use: {
        ...devices['Desktop Chrome'],
        trace: 'retain-on-failure',
        storageState: 'tests_e2e/.setup/.auth/user.json',
        viewport: {
          width: 1920,
          height: 1080
        }
      },
      dependencies: ['init data'],
    },
    {
      name: 'form intake setup',
      testMatch: "formIntake/threatAdvisorySetup.spec.ts",
      use: {
        ...devices['Desktop Chrome'],
        trace: 'retain-on-failure',
        storageState: 'tests_e2e/.setup/.auth/user.json',
        viewport: {
          width: 1920,
          height: 1080
        }
      },
      dependencies: ['init data', 'workflow setup'],
    },
    {
      // Isolated from 'chromium' on purpose: these tests consume the workflow/form intake built by
      // 'workflow setup' and 'form intake setup'. Keeping that dependency chain out of 'chromium'
      // means CI can run this project alone (e.g. --project="workflow e2e"), instead of the setup
      // projects being forced to re-run in every CI shard that filters 'chromium' tests by --grep
      // (Playwright always fully runs a project's dependencies, ignoring --grep/--grep-invert).
      name: 'workflow e2e',
      testMatch: [
        'drafts/draftsList.spec.ts',
        'drafts/threatAdvisoryHappyFlow.spec.ts',
        'drafts/threatAdvisoryOrgSharingRetry.spec.ts',
        'drafts/threatAdvisoryRejectionByAnalystOrgC.spec.ts',
        'drafts/threatAdvisoryRejectionByManagerOrgA.spec.ts',
        'drafts/threatAdvisoryRejectionByManagerOrgC.spec.ts',
      ],
      use: {
        ...devices['Desktop Chrome'],
        trace: 'retain-on-failure',
        storageState: 'tests_e2e/.setup/.auth/user.json',
        viewport: {
          width: 1920,
          height: 1080
        }
      },
      dependencies: ['init data', 'workflow setup', 'form intake setup'],
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
      testIgnore: [
        'workflow/threatAdvisoryWorkflowSetup.spec.ts',
        'formIntake/threatAdvisorySetup.spec.ts',
        'drafts/draftsList.spec.ts',
        'drafts/threatAdvisoryHappyFlow.spec.ts',
        'drafts/threatAdvisoryOrgSharingRetry.spec.ts',
        'drafts/threatAdvisoryRejectionByAnalystOrgC.spec.ts',
        'drafts/threatAdvisoryRejectionByManagerOrgA.spec.ts',
        'drafts/threatAdvisoryRejectionByManagerOrgC.spec.ts',
      ],
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
     command: `APP__BASE_PATH=${BASE_PATH} yarn start`,
     url: BASE_URL,
     reuseExistingServer: !process.env.CI,
   },

});

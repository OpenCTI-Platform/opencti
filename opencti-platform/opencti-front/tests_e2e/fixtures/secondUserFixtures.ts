import type { Page } from '@playwright/test';
import { expect, prefixUrl, test as baseTest } from './baseFixtures';

/**
 * Adds an isolated browser context to a test, so it can drive a second user
 * without signing the default one out of the session every spec shares.
 */
const test = baseTest.extend<{ secondUserPage: Page }>({
  secondUserPage: async ({ browser, baseURL, viewport, ignoreHTTPSErrors }, use) => {
    // Playwright applies the project options to a context created here, the stored admin session
    // included, and it already starts the tracing this context needs. Only the empty storage state
    // has to be asked for: it is what puts this page on the login screen.
    const context = await browser.newContext({
      baseURL,
      viewport,
      ignoreHTTPSErrors,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    const originalGoto = page.goto.bind(page);
    page.goto = (url, options) => originalGoto(prefixUrl(url), options);

    await use(page);

    await context.close();
  },
});

export { test, expect };

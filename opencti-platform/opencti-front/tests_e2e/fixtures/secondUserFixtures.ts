import type { Page } from '@playwright/test';
import { expect, prefixUrl, test as baseTest } from './baseFixtures';

/**
 * Adds an isolated browser context to a test, so it can drive a second user
 * without signing the default one out of the session every spec shares.
 */
const test = baseTest.extend<{ secondUserPage: Page }>({
  // storageState is left out on purpose: the page starts on the login screen.
  secondUserPage: async ({ browser, baseURL, viewport, ignoreHTTPSErrors }, use, testInfo) => {
    const context = await browser.newContext({ baseURL, viewport, ignoreHTTPSErrors });
    // Tracing is wired into Playwright's own context fixture, so a hand-made context records nothing.
    const withTrace = testInfo.retry > 0;
    if (withTrace) {
      await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    }
    const page = await context.newPage();
    const originalGoto = page.goto.bind(page);
    page.goto = (url, options) => originalGoto(prefixUrl(url), options);

    await use(page);

    if (withTrace) {
      const tracePath = testInfo.outputPath('second-user-trace.zip');
      await context.tracing.stop({ path: tracePath });
      await testInfo.attach('second-user-trace', { path: tracePath, contentType: 'application/zip' });
    }
    await context.close();
  },
});

export { test, expect };

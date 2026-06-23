import { expect, test } from '../fixtures/baseFixtures';
import PlaygroundPage from '../model/playground.pageModel';

// The GraphQL playground is served on a public route, so it must render
// without an authenticated session.
test.describe('GraphQL playground', { tag: ['@ce'] }, () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('should display the public playground without errors', async ({ page }) => {
    const playgroundPage = new PlaygroundPage(page);

    await playgroundPage.goto();

    // The playground title and the GraphiQL editor should be visible.
    await expect(playgroundPage.getPageTitle()).toBeVisible();
    await expect(playgroundPage.getPage()).toBeVisible();

    // The error boundary fallback must not be displayed.
    await expect(playgroundPage.getErrorMessage()).toHaveCount(0);
  });
});

import { expect, test } from '../fixtures/baseFixtures';

test('Should pass on CI even with feature flags', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('TEST E2E WITH FEATURE FLAGS')).toBeVisible();
});

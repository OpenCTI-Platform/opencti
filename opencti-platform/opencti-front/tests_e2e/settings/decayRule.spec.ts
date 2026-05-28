import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

test('Check access to the overview of a decay rule', { tag: ['@ce'] }, async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);

  // Navigate to the decay rules list (built-in rules are always seeded)
  await page.goto('/dashboard/settings/customization/decay');
  await leftBarPage.expectBreadcrumb('Settings', 'Customization', 'Decay rules');

  // Open the overview of a built-in decay rule
  await page.getByRole('link', { name: 'Built-in default' }).click();

  // The overview should display the configuration card with the expected fields
  await expect(page.getByText('Decay indicator filter', { exact: true })).toBeVisible();
  await expect(page.getByText('Lifetime (in days)', { exact: true })).toBeVisible();
});


import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

/**
 * The Defense and Data > Curation hubs ship with an empty registry: until a feature registers an
 * area or a tab, neither hub is listed in the menu, and each address opens the hub's first-use page.
 */
test.describe('Hubs without a registered page', { tag: ['@ce'] }, () => {
  test('lists neither hub in the menu', async ({ page }) => {
    await page.goto('/');
    const leftBarPage = new LeftBarPage(page);
    await leftBarPage.open();
    const nav = page.getByLabel('Main navigation', { exact: true });
    await leftBarPage.clickOnMenu('Data');
    await expect(nav.getByRole('link', { name: 'Relationships', exact: true })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Curation', exact: true })).toHaveCount(0);
    await expect(nav.getByRole('button', { name: 'Defense', exact: true })).toHaveCount(0);
    await expect(nav.getByRole('link', { name: 'Defense', exact: true })).toHaveCount(0);
  });

  test('Defense opens its first-use page from its address', async ({ page }) => {
    await page.goto('/dashboard/defense');
    const leftBarPage = new LeftBarPage(page);
    await leftBarPage.expectBreadcrumb('Defense');

    const firstUse = page.getByTestId('hub-first-use');
    await expect(firstUse).toBeVisible();
    await expect(firstUse.getByText('Turn your threat knowledge into detection and proof.')).toBeVisible();
    await expect(firstUse.getByTestId('hub-empty')).toContainText('No Defense area is available on this platform yet.');
    await expect(firstUse.getByRole('link', { name: 'Read the documentation' }))
      .toHaveAttribute('href', 'https://docs.opencti.io/latest/usage/defense-hub/');
    await expect(page.getByTestId('hub-no-access')).toHaveCount(0);
  });

  test('Defense sends a link to a missing area to its first-use page', async ({ page }) => {
    await page.goto('/dashboard/defense/unknown-area/details');
    await expect(page).toHaveURL(/\/dashboard\/defense$/);
    await expect(page.getByTestId('hub-empty')).toBeVisible();
  });

  test('Data > Curation opens its first-use page from its address', async ({ page }) => {
    await page.goto('/dashboard/data/curation');
    const leftBarPage = new LeftBarPage(page);
    await leftBarPage.expectBreadcrumb('Data', 'Curation');

    const firstUse = page.getByTestId('hub-first-use');
    await expect(firstUse).toBeVisible();
    await expect(firstUse.getByText('Keep your knowledge base clean and trustworthy.')).toBeVisible();
    await expect(firstUse.getByTestId('hub-empty')).toContainText('No Curation page is available on this platform yet.');
    await expect(firstUse.getByRole('link', { name: 'Read the documentation' }))
      .toHaveAttribute('href', 'https://docs.opencti.io/latest/usage/curation-hub/');
  });

  test('Data > Curation sends a link to a missing tab to its first-use page', async ({ page }) => {
    await page.goto('/dashboard/data/curation/unknown-tab');
    await expect(page).toHaveURL(/\/dashboard\/data\/curation$/);
    await expect(page.getByTestId('hub-empty')).toBeVisible();
  });
});

import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

/**
 * The Defense and Data > Curation hubs ship with an empty registry: until a feature registers an
 * area or a tab, each hub is a menu link to its own first-use page.
 */
test.describe('Hubs without a registered page', { tag: ['@ce'] }, () => {
  test('Defense opens its first-use page from the menu', async ({ page }) => {
    await page.goto('/');
    const leftBarPage = new LeftBarPage(page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Defense');
    await expect(page).toHaveURL(/\/dashboard\/defense$/);
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

  test('Data > Curation opens its first-use page from the menu', async ({ page }) => {
    await page.goto('/');
    const leftBarPage = new LeftBarPage(page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Data', 'Curation');
    await expect(page).toHaveURL(/\/dashboard\/data\/curation$/);
    await leftBarPage.expectBreadcrumb('Data', 'Curation');

    const firstUse = page.getByTestId('hub-first-use');
    await expect(firstUse).toBeVisible();
    await expect(firstUse.getByText('Keep your knowledge base clean and trustworthy, from one place.')).toBeVisible();
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

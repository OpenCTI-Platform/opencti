import { expect, test } from '../fixtures/baseFixtures';
import FiltersPageModel from '../model/filters.pageModel';

test('Add a new filter in the observables list and check the filter is still present when we come back to the page', async ({ page }) => {
  await page.goto('/dashboard/observations/observables');
  const filterUtils = new FiltersPageModel(page);
  await filterUtils.addFilter('Entity type', 'Artifact');
  await expect(page.getByRole('button', { name: 'Entity type = Artifact' })).toBeVisible();
  await page.goto('/dashboard/');
  await page.goto('/dashboard/observations/observables');
  await expect(page.getByRole('button', { name: 'Entity type = Artifact' })).toBeVisible();
});

import { expect, test } from '../fixtures/baseFixtures';
import DataEntitiesPage from '../model/DataEntities.pageModel';
import DataTablePage from '../model/DataTable.pageModel';

test('Toolbar actions stay visible when the columns are wider than the table', { tag: ['@ce'] }, async ({ page }) => {
  const dataEntitiesPage = new DataEntitiesPage(page);
  const dataTable = new DataTablePage(page);
  await dataEntitiesPage.goto();
  await expect(dataEntitiesPage.getPage()).toBeVisible();
  await expect(dataTable.getLineCheckbox(0)).toBeVisible();

  // Widen the Name column so that the columns no longer fit and the table scrolls horizontally.
  await dataTable.resizeColumn(1, 600);
  await dataTable.getLineCheckbox(0).click();

  const toolbar = page.getByTestId('opencti-toolbar');
  await expect(toolbar.getByText('selected')).toBeInViewport();
  await expect(toolbar.getByRole('button', { name: 'Delete' })).toBeInViewport();

  // Scrolling the table does not take the actions out of view either.
  await dataTable.container.evaluate((el) => el.scrollTo({ left: el.scrollWidth }));
  await expect(toolbar.getByText('selected')).toBeInViewport();
  await expect(toolbar.getByRole('button', { name: 'Delete' })).toBeInViewport();
});

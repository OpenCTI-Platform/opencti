import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import DataEntitiesPage from '../model/DataEntities.pageModel';
import DataTablePage from '../model/DataTable.pageModel';

/**
 * Widen a column so that the columns no longer fit and the table scrolls horizontally,
 * select the first line, then check the toolbar stays in view, before and after scrolling the table.
 */
const checkToolbarStaysVisible = async (page: Page, columnIndex: number, actionName: string) => {
  const dataTable = new DataTablePage(page);
  await expect(dataTable.getLineCheckbox(0)).toBeVisible();
  await dataTable.resizeColumn(columnIndex, 600);
  await dataTable.getLineCheckbox(0).click();

  const toolbar = page.getByTestId('opencti-toolbar');
  await expect(toolbar.getByText('selected')).toBeInViewport();
  await expect(toolbar.getByRole('button', { name: actionName })).toBeInViewport();

  await dataTable.container.evaluate((el) => el.scrollTo({ left: el.scrollWidth }));
  await expect(toolbar.getByText('selected')).toBeInViewport();
  await expect(toolbar.getByRole('button', { name: actionName })).toBeInViewport();
};

test('Toolbar actions stay visible when the columns are wider than the table', { tag: ['@ce'] }, async ({ page }) => {
  const dataEntitiesPage = new DataEntitiesPage(page);
  await dataEntitiesPage.goto();
  await expect(dataEntitiesPage.getPage()).toBeVisible();
  await checkToolbarStaysVisible(page, 1, 'Delete');
});

test('Bulk search toolbar actions stay visible when the columns are wider than the table', { tag: ['@ce'] }, async ({ page }) => {
  await page.goto('/dashboard/search_bulk?q=e2e-unknown-value-for-toolbar');
  await page.getByRole('tab', { name: 'Unknown entities' }).click();
  await checkToolbarStaysVisible(page, 0, 'Create unknown entities');
});

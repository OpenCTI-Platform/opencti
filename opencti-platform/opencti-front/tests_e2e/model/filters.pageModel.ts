import { Page, expect } from '@playwright/test';

export default class FiltersPageModel {
  constructor(private page: Page) {}

  async addFilter(filterKey: string, filterLabel: string, autoOpen = true) {
    await this.page.getByLabel('Add filter').click();
    await this.page.getByRole('option', { name: filterKey }).click();
    if (!autoOpen) {
      await this.page.getByRole('button', { name: `${filterKey} =` }).click();
    }
    await this.page.getByRole('combobox', { name: filterKey }).click();
    await this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox').check();
    return this.page.mouse.click(10, 10);
  }
  async removeLastFilter() {
    await expect(this.page.getByTestId('CancelIcon').last()).toBeVisible();
    await this.page.getByTestId('CancelIcon').last().click({ force: true});
  }
}

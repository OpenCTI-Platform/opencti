import { Page } from '@playwright/test';

export default class FiltersPageModel {
  constructor(private page: Page) {}

  async addFilterFromList(filterKey: string, filterLabel: string, autoOpen = true) {
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
    await this.page.getByTestId('CancelIcon').last().click();
  }

  async addFilterFromText(filterKey: string, entry: string) {
    await this.page.getByLabel('Add filter').click();
    await this.page.getByRole('option', { name: filterKey, exact: true }).click();
    await this.page.getByLabel(filterKey).fill(entry);
    await this.page.locator('.MuiPopover-root > .MuiBackdrop-root').click();
  }

  async addFilterFromTextAndOperator(filterKey: string, defaultOperator: string, newOperator: string, entry?: string) {
    await this.page.getByLabel('Add filter').click();
    await this.page.getByRole('option', { name: filterKey, exact: true }).click();
    await this.page.getByLabel(defaultOperator).click();
    await this.page.getByRole('option', { name: newOperator, exact: true }).click();
    if (entry) await this.page.getByLabel(filterKey).fill(entry);
    await this.page.locator('.MuiPopover-root > .MuiBackdrop-root').click();
  }

  async addFilterFromDate(filterKey: string, dateNumber: string, newOperator?: string) {
    await this.page.getByLabel('Add filter').click();
    await this.page.getByRole('option', { name: filterKey, exact: true }).click();
    if (newOperator) {
      await this.page.getByLabel('Greater than/ Equals').click();
      await this.page.getByRole('option', { name: newOperator, exact: true }).click();
    }
    await this.page.getByLabel('Choose date').click();
    await this.page.getByRole('gridcell', { name: dateNumber }).click();
    // await this.page.locator('.MuiPopover-root > .MuiBackdrop-root').click();
  }
}

import { Page, expect } from '@playwright/test';
import { awaitUntilCondition } from '../utils/utils';

export default class FiltersPageModel {
  constructor(private page: Page) {}

  async addFilter(filterKey: string, filterLabel: string, deflakeButton?: string) {
    await this.page.getByLabel('Add filter').fill(filterKey);

    await expect(this.page.getByRole('option', { name: filterKey })).toBeVisible();
    await this.page.getByRole('option', { name: filterKey }).click();

    if (deflakeButton) { // The deflakeButton is used in the context of adding filters in datatables
      const isLabelListVisible = await this.page.getByRole('combobox', { name: filterKey }).isVisible();
      if (!isLabelListVisible) {
        // This is probably a UI issue, that is random and I have no better idea so far.
        // Happens mostly when a graphQL request is done to fetch data
        // Since there is some cache the fetch is not always done
        const isFilterIconButtonVisible = async () => this.page.getByRole('button', { name: deflakeButton }).last().isVisible();
        await awaitUntilCondition(isFilterIconButtonVisible);
        await this.page.getByRole('button', { name: deflakeButton }).last().click();
      }
    }
    await expect(this.page.getByRole('combobox', { name: filterKey })).toBeVisible();
    await this.page.getByRole('combobox', { name: filterKey }).click();

    await expect(this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox')).toBeVisible();
    await this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox').check();

    return this.page.mouse.click(10, 10);
  }

  // add filters in datatables
  async addFilterInDatatable(filterKey: string, filterLabel: string, deflakeButton: string) {
    return this.addFilter(filterKey, filterLabel, deflakeButton);
  }

  async addLabelFilter(labelValue: string) {
    const filterKey = 'Label';
    const deflakeButton = 'Label =';
    return this.addFilterInDatatable(filterKey, labelValue, deflakeButton);
  }

  async addEntityTypeFilter(filterLabel: string) {
    const filterKey = 'Entity type';
    const deflakeButton = 'Entity type =';
    return this.addFilterInDatatable(filterKey, filterLabel, deflakeButton);
  }

  async removeLastFilter() {
    await expect(this.page.getByTestId('CancelIcon').last()).toBeVisible();
    await this.page.getByTestId('CancelIcon').last().click({ force: true });
  }
}

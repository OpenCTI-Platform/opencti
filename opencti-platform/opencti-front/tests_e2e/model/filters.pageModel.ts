import { Locator, Page, expect } from '@playwright/test';

export default class FiltersPageModel {
  private readonly root: Locator | Page;

  constructor(private page: Page, readonly rootLocator?: Locator) {
    this.root = rootLocator ?? page;
  }

  async addFilter(filterKey: string, filterLabel: string) {
    await this.root.getByLabel('Add filter').fill(filterKey);

    await expect(this.page.getByRole('option', { name: filterKey, exact: true })).toBeVisible();
    await this.page.getByRole('option', { name: filterKey, exact: true }).click();

    await expect(this.page.getByRole('combobox', { name: filterKey, exact: true })).toBeVisible();
    await this.page.getByRole('combobox', { name: filterKey }).click();

    await expect(this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox')).toBeVisible();
    await this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox').check();

    return this.page.mouse.click(10, 10);
  }

  async addFilterInDatatable(filterKey: string, filterLabel: string, deflakeButton: string) {
    await this.root.getByLabel('Add filter').fill(filterKey);

    await expect(this.page.getByRole('option', { name: filterKey })).toBeVisible();
    await this.page.getByRole('option', { name: filterKey }).click();

    const isLabelListVisible = await this.page.getByRole('combobox', { name: filterKey }).isVisible();
    if (!isLabelListVisible) {
      // This is probably a UI issue, that is random and I have no better idea so far.
      // Happens mostly when a graphQL request is done to fetch data
      // Since there is some cache the fetch is not always done
      await this.page.getByRole('button', { name: deflakeButton }).last().click();
    }
    await expect(this.page.getByRole('combobox', { name: filterKey })).toBeVisible();
    await this.page.getByRole('combobox', { name: filterKey }).click();

    await expect(this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox')).toBeVisible();
    await this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox').check();

    return this.page.mouse.click(10, 10);
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
    // The filter chip's remove button used to be MUI Chip's default
    // mouse-only deleteIcon (CancelIcon); it is now a real, keyboard-focusable
    // IconButton with an explicit aria-label, so target that instead.
    const removeFilterButton = this.root.getByRole('button', { name: 'Remove filter' }).last();
    await expect(removeFilterButton).toBeVisible();
    await removeFilterButton.click({ force: true });
  }
}

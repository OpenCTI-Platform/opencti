import { Locator, Page } from '@playwright/test';
import AutocompleteFieldPageModel from './AutocompleteField.pageModel';

/**
 * WORK IN PROGRESS
 */
export default class FilterFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly filtersAutocomplete: AutocompleteFieldPageModel;

  constructor(
    readonly page: Page,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByLabel('Add filter', { exact: true });
    this.filtersAutocomplete = new AutocompleteFieldPageModel(page, 'Add filter', false, rootLocator);
  }

  open() {
    return this.inputLocator.click();
  }

  async addFilter(name: string) {
    return this.filtersAutocomplete.selectOption(name);
    // return this.page.mouse.click(10, 10);
  }

  async selectFilterCondition(filterName: string, condition: string) {
    await this.page.getByText(`${filterName} =`).click();
    await this.page.getByText('Equals').click();
    return this.page.getByText(condition, { exact: true }).click();
  }
}

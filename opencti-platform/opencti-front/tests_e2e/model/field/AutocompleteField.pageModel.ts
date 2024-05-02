import { Locator, Page } from '@playwright/test';

export default class AutocompleteFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  constructor(
    private readonly page: Page,
    private readonly label: string,
    private readonly multiple: boolean,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByRole('combobox', { name: label });
    this.parentLocator = this.inputLocator.locator('../../../..');
  }

  async selectOption(option: string) {
    await this.inputLocator.click();
    await this.inputLocator.fill(option);
    const list = this.page.getByRole('listbox', { name: this.label });
    return list.getByText(option, { exact: true }).click();
  }

  getOption(option: string) {
    return this.multiple
      ? this.parentLocator.getByRole('button', { name: option })
      : this.inputLocator;
  }

  openAddOptionForm() {
    return this.parentLocator.getByRole('button', { name: 'Add', exact: true }).click();
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}

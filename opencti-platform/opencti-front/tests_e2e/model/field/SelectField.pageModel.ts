import { Locator, Page } from '@playwright/test';

export default class SelectFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  constructor(
    private readonly page: Page,
    private readonly label: string,
    private readonly multiple: boolean,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByRole('combobox', { name: label });
    this.parentLocator = this.inputLocator.locator('../..');
  }

  async selectOption(option: string) {
    await this.inputLocator.click();
    const list = this.page.getByRole('listbox', { name: this.label });
    return list.getByText(option, { exact: true }).click();
  }

  getOption(option: string) {
    return this.parentLocator.getByText(option);
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}

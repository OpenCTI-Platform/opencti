import { Locator, Page } from '@playwright/test';

export default class ConfidenceFieldPageModel {
  private readonly alertLocator: Locator;

  constructor(
    private readonly page: Page,
    private readonly label: string,
    readonly rootLocator?: Locator,
  ) {
    this.alertLocator = (rootLocator ?? page).getByRole('alert', { name: label });
  }

  getInput() {
    // By ROLE, not by label: this row shows one value twice, a number input and a
    // select, and both are named after the field — as they should be. getByLabel
    // matched both. type="number" gives the input the spinbutton role, which the
    // select cannot have.
    return this.alertLocator.getByRole('spinbutton');
  }

  getSelect() {
    return this.alertLocator.getByRole('combobox');
  }

  fillInput(value: string) {
    return this.getInput().fill(value);
  }

  async selectOption(option: string) {
    await this.getSelect().click();
    const list = this.page.getByRole('listbox', { name: this.label });
    return list.getByRole('option', { name: option }).click();
  }
}

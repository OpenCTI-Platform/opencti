import { Locator, Page } from '@playwright/test';

export default class DateFieldPageModel {
  private readonly inputLocator: Locator;

  constructor(
    private readonly page: Page,
    label: string,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByLabel(label);
  }

  getInput() {
    return this.inputLocator;
  }

  value() {
    return this.inputLocator.inputValue();
  }

  async clear() {
    await this.inputLocator.click();
    await this.page.keyboard.press('Control+A');
    return this.page.keyboard.press('Backspace');
  }

  async fill(input: string) {
    await this.inputLocator.click();
    return this.page.keyboard.type(input, { delay: 100 });
  }
}

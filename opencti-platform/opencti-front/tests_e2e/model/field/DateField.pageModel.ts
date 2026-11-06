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
    await this.page.keyboard.press('ControlOrMeta+A');
    return this.page.keyboard.press('Backspace');
  }

  async fill(input: string) {
    await this.inputLocator.click();
    // The field is split in date sections and a click puts the caret on the section under
    // the pointer, so the typing would start on an arbitrary one. Selecting every section
    // first makes it always start on the first section, whatever the locale order.
    await this.page.keyboard.press('ControlOrMeta+A');
    await this.page.keyboard.type(input, { delay: 100 });
  }
}

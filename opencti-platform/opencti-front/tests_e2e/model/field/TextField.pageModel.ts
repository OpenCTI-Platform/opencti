import { Locator, Page } from '@playwright/test';

type TextFieldPageModelType = 'text' | 'text-area' | 'rich-content';

export default class TextFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  constructor(
    readonly page: Page,
    label: string,
    type: TextFieldPageModelType,
    readonly rootLocator?: Locator,
  ) {
    const root = rootLocator ?? page;
    if (type === 'text-area') {
      this.parentLocator = root.getByText(label).locator('../../../..');
      this.inputLocator = this.parentLocator.getByTestId('text-area');
    } else if (type === 'rich-content') {
      this.parentLocator = root.getByText(label).locator('..');
      this.inputLocator = this.parentLocator.getByLabel('Editor editing area: main');
    } else {
      this.inputLocator = root.getByLabel(label);
      this.parentLocator = root.getByText(label).locator('..');
    }
  }

  get() {
    return this.inputLocator;
  }

  value() {
    return this.inputLocator.inputValue();
  }

  async clear() {
    await this.inputLocator.clear();
  }

  async fill(input: string, clear = true) {
    await this.inputLocator.click();
    if (clear) await this.clear();
    return this.inputLocator.fill(input);
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}

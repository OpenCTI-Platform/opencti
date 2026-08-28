import { Locator, Page } from '@playwright/test';

type TextFieldPageModelType = 'text' | 'text-area' | 'text-area-direct' | 'rich-content' | 'text-no-label' | 'search';

export default class TextFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  constructor(
    readonly page: Page,
    label: string,
    type: TextFieldPageModelType,
    readonly rootLocator?: Locator,
  ) {
    const root = rootLocator ?? page.locator('body');
    if (type === 'text-area') {
      this.parentLocator = root.getByText(label).locator('../../../..');
      this.inputLocator = this.parentLocator.getByTestId('text-area');
    } else if (type === 'text-area-direct') {
      this.parentLocator = root;
      this.inputLocator = root.getByTestId('text-area');
    } else if (type === 'rich-content') {
      this.parentLocator = root.getByText(label).locator('../..');
      this.inputLocator = this.parentLocator.getByLabel('Editing area: main');
    } else if (type === 'search') {
      // The design-system SearchField renders <input type="search">, which maps
      // to the ARIA searchbox role, not textbox. Its own type, rather than a
      // widened 'text-no-label', because the other three consumers of that type
      // are ordinary text inputs and must keep matching textbox.
      this.inputLocator = root.getByRole('searchbox', { name: label });
      this.parentLocator = root.getByText(label).locator('..');
    } else if (type === 'text-no-label') {
      this.inputLocator = root.getByRole('textbox', { name: label });
      this.parentLocator = root.getByText(label).locator('..');
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

import { Locator, Page } from '@playwright/test';

export default class FileFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  constructor(
    readonly page: Page,
    label: string,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByText(label);
    // Nearest ancestor that actually holds the file input, rather than a fixed
    // number of '..' hops: the FDS field puts the label in its own row, so the
    // input sits one level higher than it did under MUI.
    this.parentLocator = this.inputLocator.locator(
      'xpath=ancestor::*[.//input[@type="file"]][1]',
    );
  }

  async uploadContentFile(filePath: string) {
    await this.parentLocator.locator('input[type="file"]').setInputFiles(filePath);
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}

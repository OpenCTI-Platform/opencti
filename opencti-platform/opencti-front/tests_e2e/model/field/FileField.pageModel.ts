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
    this.parentLocator = this.inputLocator.locator('..');
  }

  async uploadContentFile(filePath: string) {
    await this.parentLocator.locator('input[type="file"]').setInputFiles(filePath);
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}

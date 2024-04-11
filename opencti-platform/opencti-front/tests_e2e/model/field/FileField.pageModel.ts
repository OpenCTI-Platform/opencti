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
    const fileChooserPromise = this.page.waitForEvent('filechooser');
    await this.inputLocator.click();
    await this.parentLocator.click();
    await this.parentLocator.getByRole('button', { name: 'Select your file', exact: true }).click();
    const fileChooser = await fileChooserPromise;
    return fileChooser.setFiles(filePath);
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}

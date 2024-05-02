import { Locator, Page } from '@playwright/test';

export default class ToolbarPageModel {
  private readonly toolbarLocator: Locator;

  constructor(private readonly page: Page) {
    this.toolbarLocator = page.getByTestId('opencti-toolbar');
  }

  async launchDelete() {
    await this.toolbarLocator.getByRole('button', { name: 'Delete' }).click();
    return this.page.getByRole('button', { name: 'Launch' }).click();
  }
}

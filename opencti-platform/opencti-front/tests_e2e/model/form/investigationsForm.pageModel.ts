import { Page } from '@playwright/test';

export default class InvestigationsFormPage {
  constructor(private page: Page) {
  }

  getNameInput() {
    return this.page.getByLabel('Name');
  }

  async fillNameInput(input: string) {
    await this.getNameInput().click();
    return this.getNameInput().fill(input);
  }

  getCloseButton() {
    return this.page.getByRole('button', { name: 'Close' });
  }

  getTagInput() {
    return this.page.getByPlaceholder('New tag');
  }

  async fillTagInput(input: string) {
    await this.getTagInput().click();
    return this.getTagInput().fill(input);
  }
}

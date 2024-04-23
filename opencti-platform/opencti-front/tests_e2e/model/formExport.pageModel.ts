import { Page } from '@playwright/test';

export default class FormExportPage {
  constructor(private page: Page) {}

  async fillContentInput(input: string) {
    await this.page.getByLabel(input).click();
  }

  async getMarkings(input: string) {
    await this.page.getByText(input).click();
  }

  async fillFileInput(input: string) {
    await this.page.getByLabel(input).click();
  }

  async getContentMarkings(input: string) {
    await this.page.getByRole('listbox').getByText(input).click();
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getCancelButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}

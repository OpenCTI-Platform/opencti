// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class IntrusionSetFormPage {
  constructor(private page: Page) {}

  getNameInput() {
    return this.page.getByRole('textbox', { name: 'Name' });
  }

  async fillNameInput(input: string) {
    await this.getNameInput().click();
    return this.getNameInput().fill(input);
  }
}

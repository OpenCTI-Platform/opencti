import { Page } from '@playwright/test';

export default class InvestigationFormPage {
  constructor(private page: Page) {}

  getNameInput() {
    return this.page.getByLabel('Name');
  }

  getDescriptionInput() {
    return this.page.getByTestId('text-area');
  }

  getSubmitButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  async fillNameInput(value: string) {
    await this.getNameInput().click();
    return this.getNameInput().fill(value);
  }

  async fillDescriptionInput(value: string) {
    await this.getDescriptionInput().click();
    return this.getDescriptionInput().fill(value);
  }
}

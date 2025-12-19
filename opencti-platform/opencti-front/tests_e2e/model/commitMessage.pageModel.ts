import { Page } from '@playwright/test';

export default class CommitMessagePage {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('commit-message-page');
  }

  getAddNewReferenceButton() {
    return this.page.locator('.MuiDialogContent-root > div > .MuiButtonBase-root');
  }

  getNewReferenceSourceNameInput() {
    return this.page.getByLabel('Source name');
  }

  async fillNewReferenceSourceNameInput(input: string) {
    await this.getNewReferenceSourceNameInput().click();
    return this.getNewReferenceSourceNameInput().fill(input);
  }

  getNewReferenceExternalIDInput() {
    return this.page.getByLabel('External ID');
  }

  async fillNewReferenceExternalIDInput(input: string) {
    await this.getNewReferenceExternalIDInput().click();
    return this.getNewReferenceExternalIDInput().fill(input);
  }

  getNewReferenceCreateButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getValidateButton() {
    return this.page.getByRole('button', { name: 'Validate' });
  }
}

import { Page } from "@playwright/test";

export class ReportFormPage {
  constructor(private page: Page) {
  }
  getNameInput() {
    return this.page.getByLabel('Name');
  }
  async fillNameInput(input: string) {
    await this.getNameInput().click();
    return this.getNameInput().fill(input);
  }
  getCloseButton(){
    return this.page.getByRole('button', { name: 'Close' });
  }
}

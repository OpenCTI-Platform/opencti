import { Page } from '@playwright/test';

export default class GroupingFormPage {
  constructor(private page: Page) {}

  async fillNameInput(input: string) {
    const element = this.page.getByLabel('Name');
    await element.click();
    await element.fill(input);
  }

  async selectContextLabel(label: string) {
    await this.page.getByLabel('Context').click();
    await this.page.getByLabel(label).click();
  }

  submit() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }
}

import { Page } from '@playwright/test';

export default class TaskPopup {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('background-task-popup');
  }

  async launchAddLabel(labelName: string) {
    // Launch background task on selected
    await this.page.getByLabel('Update', { exact: true }).getByLabel('update').click();
    await this.page.getByRole('combobox').first().click();
    await this.page.getByRole('option', { name: 'Add' }).click();
    await this.page.getByRole('combobox').nth(1).click();
    await this.page.getByRole('option', { name: 'Labels' }).click();
    await this.page.getByLabel('Values').click();

    await this.page.getByText(labelName).click({ timeout: 5000 });
    await this.page.getByRole('button', { name: 'Update' }).click();
    await this.page.getByRole('button', { name: 'Launch' }).click();
  }
}

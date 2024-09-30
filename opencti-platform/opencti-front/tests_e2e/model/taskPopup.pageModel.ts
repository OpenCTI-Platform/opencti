import { Page } from '@playwright/test';

export default class TaskPopup {
  constructor(private page: Page) {}

  async launchAddLabel(labelName: string, firstTime: boolean) {
    // Launch background task on selected
    await this.page.getByLabel('Update', { exact: true }).getByLabel('update').click();
    await this.page.getByRole('combobox').first().click();
    await this.page.getByRole('option', { name: 'Add' }).click();
    await this.page.getByRole('combobox').nth(1).click();
    await this.page.getByRole('option', { name: 'Labels' }).click();
    await this.page.getByLabel('Values').click();

    // Need to wait the request that fetch labels (in background task popup) - but only on the first call...
    try {
      await this.page.waitForResponse((resp) => resp.url().includes('/graphql') && resp.status() === 200);
    } catch (e) {
      // We don't care, sometimes label requires loading, sometimes no....
    }

    // Redo select label to make resilient above try catch.
    await this.page.getByRole('heading', { name: 'Update entities' }).click();
    await this.page.getByLabel('Values').click();

    await this.page.getByText(labelName).click();
    await this.page.getByRole('button', { name: 'Update' }).click();
    await this.page.getByRole('button', { name: 'Launch' }).click();
  }
}

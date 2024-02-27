// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class DashboardPage {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('dashboard-page');
  }

  openButtonModal() {
    return this.page.getByLabel('Create', { exact: true });
  }

  addNewDashboard() {
    return this.page.getByLabel('Create dashboard', { exact: true });
  }

  getDashboardNameInput() {
    return this.page.getByLabel('Name');
  }

  getCreateDashboardButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name }).first();
  }
}

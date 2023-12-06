import { Page } from '@playwright/test';

export default class DashboardPage {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('dashboard-page');
  }

  addNewDashboard() {
    return this.page.getByTestId('CreateDashboard');
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

import { Page } from '@playwright/test';

export default class DashboardPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('dashboard-page');
  }

  getPageTitle() {
    return this.page.getByText('Dashboards', { exact: true });
  }

  getCreateMenuButton() {
    return this.page.getByLabel('Create', { exact: true });
  }

  getImportButton() {
    return this.page.getByLabel('Import dashboard', { exact: true });
  }

  getAddNewButton() {
    return this.page.getByLabel('Create dashboard', { exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}

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

  getImportDashboardButton() {
    return this.page.getByTestId('ImportDashboard');
  }

  getAddNewDashboardButton() {
    return this.page.getByTestId('CreateDashboard');
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}

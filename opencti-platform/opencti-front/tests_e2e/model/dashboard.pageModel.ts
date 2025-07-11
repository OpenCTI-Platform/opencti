import { Page } from '@playwright/test';

export default class DashboardPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('dashboard-page');
  }

  getPageTitle() {
    // There is also a 'Dashboards' in the left menu
    return this.page.getByTestId('navigation').getByText('Dashboards', { exact: true });
  }

  getImportDashboardButton() {
    return this.page.getByRole('button', { name: 'Import Dashboard' });
  }

  getAddNewDashboardButton() {
    return this.page.getByRole('button', { name: 'Create Dashboard' });
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}

// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class DashboardPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('dashboard-page');
  }
}

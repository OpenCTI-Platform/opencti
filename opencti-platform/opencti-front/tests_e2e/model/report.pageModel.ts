import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ReportPage {
  pageUrl = '/dashboard/analyses/reports';
  constructor(private page: Page) {}

  /**
   * Reload the page (like F5), mostly used once on test start.
   * When possible please use navigateFromMenu instead it's faster.
   */
  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Analyses', 'Reports');
  }

  getPage() {
    return this.page.getByTestId('report-page');
  }

  openNewReportForm() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  closeNewreport() {
    return this.page.getByLabel('Close', { exact: true }).click();
  }

  getReportNameInput() {
    return this.page.getByLabel('Name');
  }

  getCreateReportButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }

  checkItemInList(name: string) {
    return this.getItemFromList(name).getByRole('checkbox').click();
  }

  selectAllReports() {
    return this.page.getByTestId('report-page').getByRole('listitem').getByRole('checkbox').check();
  }
}

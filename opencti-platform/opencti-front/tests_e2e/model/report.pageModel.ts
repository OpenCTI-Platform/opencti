import { Page } from '@playwright/test';

export default class ReportPage {
  pageUrl = '/dashboard/analyses/reports';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
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
}

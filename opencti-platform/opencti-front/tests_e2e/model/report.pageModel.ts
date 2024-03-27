import { Page } from '@playwright/test';

export default class ReportPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('report-page');
  }

  goToPage() {
    return this.page.getByLabel('Analyses').click();
  }

  addNewReport() {
    return this.page.getByLabel('Add', { exact: true }).click();
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
    return this.page.getByRole('link', { name }).first();
  }

  selectAllReports() {
    return this.page.getByTestId('report-page').getByRole('listitem').getByRole('checkbox').check();
  }
}

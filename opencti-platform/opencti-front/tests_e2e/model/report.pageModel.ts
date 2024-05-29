import { Page } from '@playwright/test';

export default class ReportPage {
  constructor(private page: Page) {}

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
    return this.page.getByRole('link', { name });
  }

  checkItemInList(name: string) {
    return this.getItemFromList(name).getByRole('checkbox').click();
  }
}

import { Page } from '@playwright/test';

export default class ReportDetailsPage {
  constructor(private page: Page) {}

  getReportDetailsPage() {
    return this.page.getByTestId('report-details-page');
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name });
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getObservablesTab() {
    return this.page.getByRole('tab', { name: 'Observables' });
  }

  getEditButton() {
    return this.page.getByLabel('Edit');
  }

  getExportButton() {
    return this.page.getByLabel('Quick export');
  }

  getDataList() {
    const list = this.page.getByTestId('FileExportManager');
    return list;
  }
}

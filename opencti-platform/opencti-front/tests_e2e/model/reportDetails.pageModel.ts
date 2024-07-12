import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';

export default class ReportDetailsPage {
  labelsSelect = new AutocompleteFieldPageModel(this.page, 'Labels', true);

  constructor(private page: Page) {}

  getReportDetailsPage() {
    return this.page.getByTestId('report-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getEditButton() {
    return this.page.getByLabel('Update', { exact: true });
  }

  goToOverviewTab() {
    return this.page.getByRole('tab', { name: 'Overview' }).click();
  }

  goToEntitiesTab() {
    return this.page.getByRole('tab', { name: 'Entities' }).click();
  }

  goToContentTab() {
    return this.page.getByRole('tab', { name: 'Content' }).click();
  }

  goToDataTab() {
    return this.page.getByRole('tab', { name: 'Data' }).click();
  }

  getContentFile(fileName: string) {
    return this.page.getByLabel(fileName);
  }

  goToObservablesTab() {
    return this.page.getByRole('tab', { name: 'Observables' }).click();
  }

  getTextForHeading(heading: string, text: string) {
    return this.page
      .getByRole('heading', { name: heading })
      .locator('..')
      .getByText(text);
  }

  openLabelsSelect() {
    return this.page.getByLabel('Add new labels').click();
  }

  addLabels() {
    return this.page.getByText('Add', { exact: true }).click();
  }

  getExportButton() {
    return this.page.getByLabel('Quick export');
  }

  getDataList() {
    return this.page.getByTestId('FileExportManager');
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Report actions' }).click();
    const list = this.page.getByRole('menu');
    await list.getByText('Delete', { exact: true }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  }
}

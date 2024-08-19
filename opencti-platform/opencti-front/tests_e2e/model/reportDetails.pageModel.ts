import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';
import SDOTabs from './SDOTabs.pageModel';

export default class ReportDetailsPage {
  labelsSelect = new AutocompleteFieldPageModel(this.page, 'Labels', true);
  tabs = new SDOTabs(this.page);

  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('report-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getEditButton() {
    return this.page.getByLabel('Update', { exact: true });
  }

  getContentFile(fileName: string) {
    return this.page.getByLabel(fileName);
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
    await this.page.getByRole('button', { name: 'Update' })
    .filter({ hasText: 'Update' })
    .click();
    await this.page.getByRole('button', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  }
}

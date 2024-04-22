import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';

export default class IncidentResponseDetailsPage {
  labelsSelect = new AutocompleteFieldPageModel(this.page, 'Labels', true);

  constructor(private page: Page) {}

  getIncidentResponseDetailsPage() {
    return this.page.getByTestId('incident-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getEditButton() {
    return this.page.getByLabel('Edit');
  }

  goToOverviewTab() {
    return this.page.getByRole('tab', { name: 'Overview' }).click();
  }

  goToEntitiesTab() {
    return this.page.getByRole('tab', { name: 'Entities' }).click();
  }

  goToDataTab() {
    return this.page.getByRole('tab', { name: 'Data' }).click();
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

  async delete() {
    await this.page.getByRole('button', { name: 'Incident response actions' }).click();
    const list = this.page.getByRole('menu');
    await list.getByText('Delete', { exact: true }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  }
}
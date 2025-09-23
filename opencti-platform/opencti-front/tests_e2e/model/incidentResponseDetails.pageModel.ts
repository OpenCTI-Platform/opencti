import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';
import SDOOverview from './SDOOverview.pageModel';
import SDOTabs from './SDOTabs.pageModel';

export default class IncidentResponseDetailsPage {
  labelsSelect = new AutocompleteFieldPageModel(this.page, 'Labels', true);
  overview = new SDOOverview(this.page);
  tabs = new SDOTabs(this.page);

  constructor(private page: Page) {}

  getIncidentResponseDetailsPage() {
    return this.page.getByTestId('incident-details-page');
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
    await this.page.getByRole('button', { name: 'Popover of actions' })
      .click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }
}

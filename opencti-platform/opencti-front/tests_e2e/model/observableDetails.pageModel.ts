import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class ObservableDetailsPage {
  tabs = new SDOTabs(this.page);
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('observable-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getEnrichButton() {
    return this.page.getByLabel('Enrichment');
  }

  closeEnrichment() {
    return this.page.getByRole('button', { name: 'Close' }).click();
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }
}

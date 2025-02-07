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
}

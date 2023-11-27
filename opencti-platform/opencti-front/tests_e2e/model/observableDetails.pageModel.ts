import { Page } from "@playwright/test";

export default class ObservableDetailsPage {
  constructor (private page: Page) {}

  getFinancialDataDetailsPage() {
    return this.page.getByTestId('financialData-details-page');
  }

  getTitle() {
    return this.page.getByTestId('observable-title');
  }
}

import { Page } from "@playwright/test";

export default class ObservablePage {
  constructor (private page: Page) {}

  getPage() {
    return this.page;
  }

  addNewObservable() {
    return this.page.getByLabel('Add', { exact: true }).click();
  }

  getCreateObservableButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  addFinancialAccount() {
    return this.page.getByTestId('Financial-Account').click();
  }

  addFinancialAsset() {
    return this.page.getByTestId('Financial-Asset').click();
  }

  addFinancialTransaction() {
    return this.page.getByTestId('Financial-Transaction').click();
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name }).first();
  }
}

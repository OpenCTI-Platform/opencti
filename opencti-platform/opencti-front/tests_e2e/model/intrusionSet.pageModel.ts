import { Page } from '@playwright/test';

export default class IntrusionSetPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('instrusionSet-knowledge');
  }

  addNewIntrusionSet() {
    return this.page.getByLabel('Create Intrusion Set', { exact: true }).click();
  }

  getCreateIntrusionSetButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name }).first();
  }
}

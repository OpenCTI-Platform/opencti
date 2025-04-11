import { Page } from '@playwright/test';

export default class CaseRfiPage {
  constructor(private page: Page) {}

  getCaseRfiFormCreate() {
    return this.page.getByRole('button', { name: 'Create request for information' });
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}

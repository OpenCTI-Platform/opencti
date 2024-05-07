import { Page } from '@playwright/test';

export default class ObservablesTabPageModel {
  constructor(private page: Page) {}

  clickAddObservables() {
    return this.page.getByLabel('Add', { exact: true }).click();
  }

  addObservable(name: string) {
    const parent = this.page.getByRole('heading', { name: 'Add entities' }).locator('../..');
    return parent.getByRole('button', { name }).click();
  }

  closeAddObservable() {
    const parent = this.page.getByRole('heading', { name: 'Add entities' }).locator('../..');
    return parent.getByLabel('Close').click();
  }
}

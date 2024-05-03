import { Page } from '@playwright/test';

export default class EntitiesTabPageModel {
  constructor(private page: Page) {}

  clickAddEntities() {
    return this.page.getByLabel('Add', { exact: true }).click();
  }

  addEntity(name: string) {
    const parent = this.page.getByRole('heading', { name: 'Add entities' }).locator('../..');
    return parent.getByText(name, { exact: true }).click();
  }
}

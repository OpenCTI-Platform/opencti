import { Page } from '@playwright/test';
import TextFieldPageModel from './field/TextField.pageModel';

export default class EntitiesTabPageModel {
  private entireTab = this.page.getByRole('heading', { name: 'Add entities' }).locator('../../..');
  private searchField = new TextFieldPageModel(this.page, 'Search', 'text-no-label', this.entireTab);

  constructor(private page: Page) {}

  clickAddEntities() {
    return this.page.getByLabel('Add', { exact: true }).click();
  }

  addEntity(name: string) {
    return this.entireTab.getByRole('button', { name }).click();
  }

  closeAddEntity() {
    return this.entireTab.getByLabel('Close').click();
  }

  async search(search: string) {
    await this.searchField.fill(search);
    return this.page.keyboard.press('Enter');
  }
}

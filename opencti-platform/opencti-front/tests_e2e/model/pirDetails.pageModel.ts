import { Page } from '@playwright/test';
import PirTabsPage from './pirTabs.pageModel';

export default class PirDetailsPageModel {
  tabs = new PirTabsPage(this.page);

  constructor(private page: Page) {}

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getDescription(description: string) {
    return this.page.getByText(description, { exact: true });
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }

  getEntityTypeCount(label: string) {
    return this.page.getByTestId(`pir-overview-count-${label}`);
  }

  getTopAuthorEntities(author: string) {
    return this.page.getByTestId('pir-top-authors-entities').getByText(author);
  }

  getTopAuthorRelationships(author: string) {
    return this.page.getByTestId('pir-top-authors-relationships').getByText(author);
  }
}

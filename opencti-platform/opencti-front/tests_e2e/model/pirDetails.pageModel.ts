import { Page } from '@playwright/test';
import PirTabsPage from './pirTabs.pageModel';

export default class PirDetailsPageModel {
  tabs = new PirTabsPage(this.page);

  constructor(private page: Page) {}

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }
}

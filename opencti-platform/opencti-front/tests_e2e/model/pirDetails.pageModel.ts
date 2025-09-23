import { Page } from '@playwright/test';
import PirTabsPage from './pirTabs.pageModel';
import DataTablePage from './DataTable.pageModel';

export default class PirDetailsPageModel {
  tabs = new PirTabsPage(this.page);
  dataTable = new DataTablePage(this.page);

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

  toggleDetails() {
    return this.page.getByText('Rescan period (days)').click();
  }

  getEntityTypeCount(label: string) {
    return this.page.getByTestId(`pir-overview-count-${label}`);
  }

  getTopAuthorEntities(author: string) {
    return this.page
      .getByRole('heading', { name: 'Top authors of threat entities' })
      .locator('../..')
      .getByText(author);
  }

  getTopAuthorRelationships(author: string) {
    return this.page
      .getByRole('heading', { name: 'Top authors of relationships from threats' })
      .locator('../..')
      .getByText(author);
  }

  getNewsFeedItem(news: string) {
    return this.page
      .getByRole('heading', { name: 'News feed' })
      .locator('../..')
      .getByText(news);
  }
}

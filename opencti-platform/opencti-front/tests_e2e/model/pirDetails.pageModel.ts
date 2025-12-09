import { Page } from '@playwright/test';
import PirTabsPage from './pirTabs.pageModel';
import DataTablePage from './DataTable.pageModel';
import CardPage from './card.pageModel';

export default class PirDetailsPageModel {
  card = new CardPage(this.page);
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
    return this.page.getByTestId(`card-number-${label}`);
  }

  getTopAuthorEntities(author: string) {
    return this.card
      .getTextInCard('Top authors of threat entities', author);
  }

  getTopAuthorRelationships(author: string) {
    return this.card
      .getTextInCard('Top authors of relationships from threats', author);
  }

  getNewsFeedItem(news: string) {
    return this.card
      .getTextInCard('News feed', news);
  }
}

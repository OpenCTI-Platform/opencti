import { Page } from '@playwright/test';
import CardPage from './card.pageModel';
import DataTablePage from './DataTable.pageModel';
import SecurityCoverageTabsPage from './securityCoverageTabs.pageModel';

export default class SecurityCoverageDetailsPage {
  card = new CardPage(this.page);
  tabs = new SecurityCoverageTabsPage(this.page);
  dataTable = new DataTablePage(this.page);

  constructor(private page: Page) {}

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }
}

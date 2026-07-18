import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class IntegrationsPage {
  pageUrl = '/dashboard/integrations/deployed';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Integrations');
  }

  async switchToTab(tab: 'deployed' | 'available') {
    await this.page.getByTestId(`integrations-tab-${tab}`).click();
  }

  getPage() {
    return this.page.getByTestId('integrations-page');
  }

  getCatalogPage() {
    return this.page.getByTestId('catalog-page');
  }
}

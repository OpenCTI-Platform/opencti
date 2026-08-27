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

  async search(text: string) {
    const input = this.page.getByTestId('integrations-search-input').locator('input');
    await input.fill(text);
    await input.press('Enter');
  }

  /** Deployed tab only. Row markup differs between the "cards" and "lines" view modes. */
  getDeployedRow(name: string) {
    return this.page.locator('[data-testid="integration-line"], [data-testid="integration-card"]').filter({ hasText: name });
  }

  /** Deployed tab only - deletes the matching integration instance, if any, so re-runs don't hit a "name already exists" error. */
  async deleteDeployedIfExists(name: string) {
    await this.search(name);
    const row = this.getDeployedRow(name);
    if (await row.count() === 0) return;
    await row.getByLabel('Open menu').click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    await this.page.getByRole('button', { name: 'Confirm' }).click();
    await row.waitFor({ state: 'detached' });
  }

  getPage() {
    return this.page.getByTestId('integrations-page');
  }

  getCatalogPage() {
    return this.page.getByTestId('catalog-page');
  }

  getDeployedPage() {
    return this.page.getByTestId('deployed-page');
  }
}

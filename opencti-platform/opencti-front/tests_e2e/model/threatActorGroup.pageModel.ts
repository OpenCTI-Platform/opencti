import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ThreatActorGroupPage {
  pageUrl = '/dashboard/threats/threat_actors_group';
  constructor(private page: Page) {}

  /**
   * Reload the page (like F5), mostly used once on test start.
   * When possible please use navigateFromMenu instead it's faster.
   */
  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Threats', 'Threat actors (group)');
  }

  getPage() {
    return this.page.getByTestId('threat-actor-group-page');
  }

  getItemFromListWithUrl(name: string) {
    return this.page.getByRole('link', { name }).click();
  }
}

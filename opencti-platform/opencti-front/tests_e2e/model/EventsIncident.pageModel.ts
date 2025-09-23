import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class EventsIncidentPage {
  pageUrl = '/dashboard/events/incidents';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  getPage() {
    return this.page.getByTestId('incident-page');
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Events', 'Incidents');
  }
}

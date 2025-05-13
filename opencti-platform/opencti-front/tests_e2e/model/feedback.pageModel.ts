import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class FeedbackPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('feedback-page');
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Cases', 'Feedbacks');
  }
}

import { Page } from '@playwright/test';

export default class CardPage {
  constructor(private page: Page) {}

  getCard(title: string) {
    return this.page.getByText(title).locator('../..');
  }

  getTextInCard(title: string, text: string) {
    const card = this.getCard(title);
    return card.getByText(text);
  }
}

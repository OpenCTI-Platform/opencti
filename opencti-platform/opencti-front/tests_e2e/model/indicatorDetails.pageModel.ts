import { Page } from '@playwright/test';

export default class IndicatorDetailsPageModel {
  constructor(private page: Page) {
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }
}

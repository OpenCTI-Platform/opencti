import { Page } from '@playwright/test';

export default class DataProcessingTasksPage {
  pageUrl = '/dashboard/data/processing/tasks';

  constructor(private page: Page) {
  }

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  getPage() {
    return this.page.getByTestId('processing-tasks-page');
  }
}

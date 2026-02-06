import { Page } from '@playwright/test';
import { waitAndRefreshUntilFirstTaskInStatus } from '../backgroundTaskCheck-utils';
import { sleep } from '../utils';
import { expect } from '../fixtures/baseFixtures';

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

  async waitForTaskCompletion(page: Page) {
    // Region Background task page
    await sleep(3000); // Wait 3 secs for task creation
    await this.goto();
    await expect(this.getPage()).toBeVisible();

    // Wait until at least one is complete
    await waitAndRefreshUntilFirstTaskInStatus(page, this, 'Complete', true);
    await expect(page.getByText('Complete').first()).toBeVisible();

    // Then wait until no more processing "Processing" or "Waiting"
    await waitAndRefreshUntilFirstTaskInStatus(page, this, 'Waiting', false);
    await expect(page.getByText('Waiting')).toBeHidden();

    await waitAndRefreshUntilFirstTaskInStatus(page, this, 'Processing', false);
    await expect(page.getByText('Processing')).toBeHidden();

    // Then wait until the second one moves to "Complete" -> both are Complete we are good.
    await waitAndRefreshUntilFirstTaskInStatus(page, this, 'Complete', true);
    await expect(page.getByText('Complete').first()).toBeVisible();
    // END Region Background task page
  }
}

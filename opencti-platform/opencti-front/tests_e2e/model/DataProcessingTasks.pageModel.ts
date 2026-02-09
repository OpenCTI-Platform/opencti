import { Page } from '@playwright/test';
import { sleep } from '../utils/utils';
import { expect } from '../fixtures/baseFixtures';

/**
 * Goal: validate that background tasks are executed on the expected list of entity.
 * -------------------
 * Go on Incident
 * Filter by label "background-task"
 * Select all
 * Add 'background-task-filter-add-label' to all
 * Search by text one incident
 * Select all
 * Add 'background-task-search-add-label' to all
 * Go in data > entities
 * Verify entity count for both labels 'background-task-filter-add-label' and 'background-task-search-add-label'
 * @param page
 */

const waitAndRefreshUntilFirstTaskInStatus = async (page: Page, tasksPage: DataProcessingTasksPage, status: string, expectVisible: boolean) => {
  await tasksPage.goto();
  await expect(tasksPage.getPage()).toBeVisible();

  const loopCount = 20; // 10*6000 = 2' max
  let loopCurrent = 0;

  const isOneStatusTaskOk = async () => {
    await sleep(6000);
    await tasksPage.goto();
    if (expectVisible) {
      await expect(tasksPage.getPage()).toBeVisible();
      const isOneOrMoreStatusVisible = await page.getByText(status).first().isVisible();
      return isOneOrMoreStatusVisible;
    }
    await expect(tasksPage.getPage()).toBeHidden();
    const isOneOrMoreStatusHidden = await page.getByText(status).first().isHidden();
    return isOneOrMoreStatusHidden;
  };

  let isStatusOk = await isOneStatusTaskOk();
  while (!isStatusOk && loopCurrent < loopCount) {
    isStatusOk = await isOneStatusTaskOk();
    loopCurrent += 1;
  }
};

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

  async waitForTaskCompletion() {
    // Region Background task page
    await sleep(3000); // Wait 3 secs for task creation
    await this.goto();
    await expect(this.getPage()).toBeVisible();

    // Wait until at least one is complete
    await waitAndRefreshUntilFirstTaskInStatus(this.page, this, 'Complete', true);
    await expect(this.page.getByText('Complete').first()).toBeVisible();

    // Then wait until no more processing "Processing" or "Waiting"
    await waitAndRefreshUntilFirstTaskInStatus(this.page, this, 'Waiting', false);
    await expect(this.page.getByText('Waiting')).toBeHidden();

    await waitAndRefreshUntilFirstTaskInStatus(this.page, this, 'Processing', false);
    await expect(this.page.getByText('Processing')).toBeHidden();

    // Then wait until the second one moves to "Complete" -> both are Complete we are good.
    await waitAndRefreshUntilFirstTaskInStatus(this.page, this, 'Complete', true);
    await expect(this.page.getByText('Complete').first()).toBeVisible();
    // END Region Background task page
  }
}

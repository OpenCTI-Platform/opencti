import { expect } from './fixtures/baseFixtures';
import DataProcessingTasksPage from './model/DataProcessingTasks.pageModel';
import { Page } from '@playwright/test';
import { sleep } from './utils';

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

export const waitAndRefreshUntilFirstTaskInStatus = async (page: Page, tasksPage: DataProcessingTasksPage, status: string, expectVisible: boolean) => {
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

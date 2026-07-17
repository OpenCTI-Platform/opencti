import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import DataProcessingTasksPage from '../model/DataProcessingTasks.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import { sleep } from '../utils';
import { runBackgroundTaskOnIncidentByFilter, runBackgroundTaskOnIncidentBySearch, searchOnDataEntitiesPerLabels } from './backgroudTaskSteps';

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

  const checkStatus = async () => {
    await tasksPage.goto();
    if (expectVisible) {
      await expect(tasksPage.getPage()).toBeVisible();
      return page.getByText(status).first().isVisible();
    }
    return page.getByText(status).first().isHidden();
  };

  let isStatusOk = await checkStatus();
  while (!isStatusOk && loopCurrent < loopCount) {
    await sleep(6000);
    isStatusOk = await checkStatus();
    loopCurrent += 1;
  }
};

test('Verify background tasks execution', { tag: ['@ce', '@mutation'] }, async ({ page }) => {
  const incidentPage = new EventsIncidentPage(page);
  const tasksPage = new DataProcessingTasksPage(page);

  await incidentPage.goto();
  await expect(incidentPage.getPage()).toBeVisible();

  await runBackgroundTaskOnIncidentByFilter(page, false);
  await runBackgroundTaskOnIncidentBySearch(page, false);

  // Region Background task page
  await tasksPage.goto();
  await expect(tasksPage.getPage()).toBeVisible();

  // Wait until at least one is complete
  await waitAndRefreshUntilFirstTaskInStatus(page, tasksPage, 'Complete', true);
  await expect(page.getByText('Complete').first()).toBeVisible();

  // Then wait until no more processing "Processing" or "Waiting"
  await waitAndRefreshUntilFirstTaskInStatus(page, tasksPage, 'Waiting', false);
  await expect(page.getByText('Waiting')).toBeHidden();

  await waitAndRefreshUntilFirstTaskInStatus(page, tasksPage, 'Processing', false);
  await expect(page.getByText('Processing')).toBeHidden();

  // Then wait until the second one moves to "Complete" -> both are Complete we are good.
  await waitAndRefreshUntilFirstTaskInStatus(page, tasksPage, 'Complete', true);
  await expect(page.getByText('Complete').first()).toBeVisible();
  // END Region Background task page

  await searchOnDataEntitiesPerLabels(page, false);
});

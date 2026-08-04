import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import DataProcessingTasksPage from '../model/DataProcessingTasks.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
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
 */

/**
 * Waits for a background task to reach the expected status using Playwright's
 * built-in retry mechanism (toPass) instead of manual sleep loops.
 */
const waitForTaskStatus = async (
  page: Page,
  tasksPage: DataProcessingTasksPage,
  status: string,
  expectVisible: boolean,
) => {
  await expect(async () => {
    await tasksPage.goto();
    if (expectVisible) {
      await expect(page.getByText(status).first()).toBeVisible();
    } else {
      await expect(page.getByText(status)).toBeHidden();
    }
  }).toPass({
    intervals: [2_000, 4_000, 6_000, 8_000, 10_000],
    timeout: 120_000,
  });
};

test('Verify background tasks execution', { tag: ['@ce', '@mutation', '@group1'] }, async ({ page }) => {
  const incidentPage = new EventsIncidentPage(page);
  const tasksPage = new DataProcessingTasksPage(page);

  await incidentPage.goto();
  await expect(incidentPage.getPage()).toBeVisible();

  await runBackgroundTaskOnIncidentByFilter(page, false);
  await runBackgroundTaskOnIncidentBySearch(page, false);

  // Wait for task page to be accessible (replaces sleep(3000))
  await expect(async () => {
    await tasksPage.goto();
    await expect(tasksPage.getPage()).toBeVisible();
  }).toPass({
    intervals: [1_000, 2_000, 3_000],
    timeout: 10_000,
  });

  // Wait until at least one is complete
  await waitForTaskStatus(page, tasksPage, 'Complete', true);

  // Wait until no more "Waiting" tasks
  await waitForTaskStatus(page, tasksPage, 'Waiting', false);

  // Wait until no more "Processing" tasks
  await waitForTaskStatus(page, tasksPage, 'Processing', false);

  // Confirm final state: all tasks Complete
  await waitForTaskStatus(page, tasksPage, 'Complete', true);

  await searchOnDataEntitiesPerLabels(page, false);
});

import DataProcessingTasksPage from '../model/DataProcessingTasks.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import { sleep } from '../utils';
import { runBackgroundTaskOnIncidentByFilter, runBackgroundTaskOnIncidentBySearch, searchOnDataEntitiesPerLabels } from './backgroudTaskSteps';
import { expect, test } from '../fixtures/baseFixtures';
import { waitAndRefreshUntilFirstTaskInStatus } from '../backgroundTaskCheck-utils';

test('Verify background tasks execution', { tag: ['@ce', '@mutation'] }, async ({ page }) => {
  const incidentPage = new EventsIncidentPage(page);
  const tasksPage = new DataProcessingTasksPage(page);

  await incidentPage.goto();
  await expect(incidentPage.getPage()).toBeVisible();

  await runBackgroundTaskOnIncidentByFilter(page, false);
  await runBackgroundTaskOnIncidentBySearch(page, false);

  // Region Background task page
  await sleep(3000); // Wait 3 secs for task creation
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

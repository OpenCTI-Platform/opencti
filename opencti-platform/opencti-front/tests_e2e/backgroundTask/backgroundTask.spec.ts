import DataProcessingTasksPage from '../model/DataProcessingTasks.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import { runBackgroundTaskOnIncidentByFilter, runBackgroundTaskOnIncidentBySearch, searchOnDataEntitiesPerLabels } from './backgroudTaskSteps';
import { expect, test } from '../fixtures/baseFixtures';

test('Verify background tasks execution', { tag: ['@ce', '@mutation'] }, async ({ page }) => {
  const incidentPage = new EventsIncidentPage(page);
  const tasksPage = new DataProcessingTasksPage(page);

  await incidentPage.goto();
  await expect(incidentPage.getPage()).toBeVisible();

  await runBackgroundTaskOnIncidentByFilter(page, false);
  await runBackgroundTaskOnIncidentBySearch(page, false);

  await tasksPage.waitForTaskCompletion(page);

  await searchOnDataEntitiesPerLabels(page, false);
});

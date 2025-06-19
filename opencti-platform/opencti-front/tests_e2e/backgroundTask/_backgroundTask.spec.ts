import { expect, test } from '../fixtures/baseFixtures';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import { runBackgroundTaskOnIncidentByFilter, runBackgroundTaskOnIncidentBySearch, searchOnDataEntitiesPerLabels } from './backgroudTaskSteps';

/**
 * Goal: validate that background tasks navigation is fine before actually running background tasks.
 * Use same method but with dryRun = true;
 * -------------------
 * @param page
 */

test('Verify background tasks pre-requisites on incident search', async ({ page }) => {
  const incidentPage = new EventsIncidentPage(page);

  await incidentPage.goto();
  await expect(incidentPage.getPage()).toBeVisible();

  await runBackgroundTaskOnIncidentByFilter(page, true);
  await runBackgroundTaskOnIncidentBySearch(page, true);
});

test('Verify background tasks pre-requisites on data entity search', async ({ page }) => {
  await searchOnDataEntitiesPerLabels(page, true);
});

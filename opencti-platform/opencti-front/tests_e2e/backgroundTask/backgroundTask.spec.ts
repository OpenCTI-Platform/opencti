import { expect, test } from '../fixtures/baseFixtures';
import DataProcessingTasksPage from '../model/DataProcessingTasks.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import DataEntitiesPage from '../model/DataEntities.pageModel';
import { sleep } from '../utils';
import FiltersPageModel from '../model/filters.pageModel';
import SearchPageModel from '../model/search.pageModel';
import TaskPopup from '../model/taskPopup.pageModel';
import DataTablePage from '../model/DataTable.pageModel';

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
test('Verify background tasks execution', { tag: ['@mutation', '@incident', '@task', '@filter'] }, async ({ page }) => {
  const incidentPage = new EventsIncidentPage(page);
  const filter = new FiltersPageModel(page);
  const search = new SearchPageModel(page);
  const tasksPage = new DataProcessingTasksPage(page);
  const taskPopup = new TaskPopup(page);
  const dataTable = new DataTablePage(page);

  await incidentPage.goto();
  await expect(incidentPage.getPage()).toBeVisible();

  // Filter on label
  await filter.addFilter('Label', 'background-task', true);
  await expect(dataTable.getNumberElements(2)).toBeVisible();
  await incidentPage.goto();

  // Select all
  await dataTable.getCheckAll().click();
  await taskPopup.launchAddLabel('background-task-filter-add-label', true);
  await expect(incidentPage.getPage()).toBeVisible();

  // Clear filter on label
  await filter.removeLastFilter();

  // Filter with a search
  await search.addSearch('"Find this incident in test please"');
  await expect(dataTable.getNumberElements(1)).toBeVisible();
  await dataTable.getCheckAll().click();
  await taskPopup.launchAddLabel('background-task-search-add-label', false);
  await sleep(3000); // Wait 3 secs for task creation
  await tasksPage.goto();
  await expect(tasksPage.getPage()).toBeVisible();

  // Wait until no task are in status "Waiting" in the page
  // Max 5 times 5s
  let loopCount = 5;
  let isTaskProcessing = true;
  while (loopCount > 0 && isTaskProcessing) {
    // eslint-disable-next-line no-await-in-loop
    await sleep(5000);
    // eslint-disable-next-line no-await-in-loop
    await tasksPage.goto(); // we need to force refresh page
    // eslint-disable-next-line no-await-in-loop
    isTaskProcessing = await page.getByText('Waiting').first().isVisible({ timeout: 200 });
    loopCount -= 1;
  }
  await expect(page.getByText('Waiting')).toBeHidden({ timeout: 200 });

  // Go on the general Data > entities
  const entitiesPage = new DataEntitiesPage(page);
  await entitiesPage.goto();
  await expect(entitiesPage.getPage()).toBeVisible();

  // Filter by the new label
  await filter.addFilter('Label', 'background-task-filter-add-label', true);
  await expect(dataTable.getNumberElements(3)).toBeVisible(); // 2 by this test + 1 in stix imported data

  // Clear filter on label
  await filter.removeLastFilter();

  await filter.addFilter('Label', 'background-task-search-add-label', true);
  if (!await dataTable.getNumberElements(2).isVisible({ timeout: 500 })) {
    // Try to reload page in case it's a flake.
    await entitiesPage.goto();
  }
  await expect(dataTable.getNumberElements(2)).toBeVisible(); // 1 by this test + 1 in stix imported data
});

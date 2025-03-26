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

  // Select all
  await dataTable.getCheckAll().click();
  await taskPopup.launchAddLabel('background-task-filter-add-label');

  // Need to wait after click on "Launch" that the popup goes away.
  await expect(taskPopup.getPage().getByText('Launch a background task')).not.toBeVisible({ timeout: 3000 });

  await expect(incidentPage.getPage()).toBeVisible();

  // Clear filter on label 'background-task'
  await filter.removeLastFilter();

  // Filter with a search
  await search.addSearch('findMeWithSearchID');
  await expect(dataTable.getNumberElements(1), 'An exact search with no label should match only one incident.').toBeVisible();
  await dataTable.getCheckAll().click();
  await taskPopup.launchAddLabel('background-task-search-add-label');
  // Need to wait after click on "Launch" that the popup goes away.
  await expect(taskPopup.getPage().getByText('Launch a background task')).not.toBeVisible({ timeout: 3000 });

  // Region Background task page
  await sleep(3000); // Wait 3 secs for task creation
  await tasksPage.goto();
  await expect(tasksPage.getPage()).toBeVisible();

  // Wait until at least one is complete
  await expect(page.getByText('Complete').first()).toBeVisible();
  const loopCount = 10; // 10*5000 = 50s max
  let loopCurrent = 0;

  const isOneWaitingTaskPresent = async () => {
    await sleep(5000);
    await tasksPage.goto();
    await expect(tasksPage.getPage()).toBeVisible();
    const isOneOrMoreWaitingVisible = await page.getByText('Waiting').first().isVisible();
    return isOneOrMoreWaitingVisible;
  };

  let isWaitingVisible = await isOneWaitingTaskPresent();
  while (isWaitingVisible && loopCurrent < loopCount) {
    // eslint-disable-next-line no-await-in-loop
    isWaitingVisible = await isOneWaitingTaskPresent();
    loopCurrent += 1;
  }
  await expect(page.getByText('Waiting')).toBeHidden();
  await expect(page.getByText('Complete')).toBeVisible();
  // END Region Background task page

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

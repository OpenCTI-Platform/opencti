import { Page } from '@playwright/test';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import DataTablePage from '../model/DataTable.pageModel';
import TaskPopup from '../model/taskPopup.pageModel';
import FiltersPageModel from '../model/filters.pageModel';
import { expect } from '../fixtures/baseFixtures';
import SearchPageModel from '../model/search.pageModel';
import DataEntitiesPage from '../model/DataEntities.pageModel';
import { sleep } from '../utils';

export const runBackgroundTaskOnIncidentByFilter = async (page: Page, dryRun: boolean) => {
  const incidentPage = new EventsIncidentPage(page);
  const dataTable = new DataTablePage(page);
  const taskPopup = new TaskPopup(page);
  const filter = new FiltersPageModel(page);

  // Filter on label
  await filter.addLabelFilter('background-task');
  await expect(dataTable.getNumberElements(2)).toBeVisible();

  if (!dryRun) {
    // Select all
    await dataTable.getCheckAll().click();
    await taskPopup.launchAddLabel('background-task-filter-add-label');

    // Need to wait after click on "Launch" that the popup goes away.
    await expect(taskPopup.getPage().getByText('Launch a background task')).not.toBeVisible({ timeout: 3000 });

    await expect(incidentPage.getPage()).toBeVisible();
  }

  // Clear filter on label 'background-task'
  await filter.removeLastFilter();
};

export const runBackgroundTaskOnIncidentBySearch = async (page: Page, dryRun: boolean) => {
  const search = new SearchPageModel(page);
  const taskPopup = new TaskPopup(page);
  const dataTable = new DataTablePage(page);

  // Filter with a search
  await search.addSearch('findMeWithSearchID');
  await expect(dataTable.getNumberElements(1), 'An exact search with no label should match only one incident.').toBeVisible();
  if (!dryRun) {
    await dataTable.getCheckAll().click();
    await taskPopup.launchAddLabel('background-task-search-add-label');
    // Need to wait after click on "Launch" that the popup goes away.
    await expect(taskPopup.getPage().getByText('Launch a background task')).not.toBeVisible({ timeout: 3000 });
  }
};

export const searchOnDataEntitiesPerLabels = async (page: Page, dryRun: boolean) => {
  const filter = new FiltersPageModel(page);
  const dataTable = new DataTablePage(page);

  // Go on the general Data > entities
  const entitiesPage = new DataEntitiesPage(page);
  await entitiesPage.goto();
  await expect(entitiesPage.getPage()).toBeVisible();

  // Filter by the new label
  await filter.addLabelFilter('background-task-filter-add-label');
  if (!dryRun) {
    await expect(dataTable.getNumberElements(3)).toBeVisible(); // 2 by this test + 1 in stix imported data
  }

  // Clear filter on label
  await filter.removeLastFilter();

  await filter.addLabelFilter('background-task-search-add-label');
  if (!dryRun) {
    await sleep(3000);
    if (!await dataTable.getNumberElements(2).isVisible({ timeout: 500 })) {
      // Try to reload page in case it's a flake.
      await entitiesPage.goto();
    }
    await expect(dataTable.getNumberElements(2)).toBeVisible(); // 1 by this test + 1 in stix imported data
  }
  // Clear filter on label
  await filter.removeLastFilter();
};

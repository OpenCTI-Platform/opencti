import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import DataTablePage from '../model/DataTable.pageModel';
import TaskPopup from '../model/taskPopup.pageModel';
import { checkBackgroundTasksCompletion } from '../utils/backgroundTaskCheck-utils';
import { v4 as uuid } from 'uuid';
import FiltersPageModel from '../model/filters.pageModel';

test.describe('Drafts - Entities and background tasks', { tag: ['@ce'] }, () => {
  const draftName = `Draft E2E - ${Date.now()}`;
  const malwareName = `malware in draft- ${uuid()}`;
  const labelToApply = 'background-task-filter-add-label';

  test('should create a draft, add a malware in it and do a background task of update for the entities in the draft', async ({ page, request }) => {
    const Drafts = new DraftsPage(page);
    const taskPopup = new TaskPopup(page);
    const dataTable = new DataTablePage(page);
    const filter = new FiltersPageModel(page);

    // navigate in the drafts list
    await Drafts.navigate();

    // create a new draft
    await Drafts.createDraft({ name: draftName });
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // enter in the draft
    await Drafts.getDraft(draftName).click();

    // check we are in the 'entities' tab
    await expect(page.getByRole('tab', { name: 'Entities', selected: true })).toBeVisible();

    // add a malware in the draft
    await Drafts.addEntityToDraft({
      type: 'Malware',
      name: malwareName,
    });

    // check the malware is in the list
    await expect(Drafts.getEntityInList(malwareName)).toBeVisible();

    // go under the 'observables' tab and check there is not the malware
    await page.getByRole('tab', { name: 'Observables' }).click();
    await expect(page.getByRole('tab', { name: 'Observables', selected: true })).toBeVisible();
    await expect(Drafts.getEntityInList(malwareName)).not.toBeVisible();

    // go back to the 'entities' tab
    await page.getByRole('tab', { name: 'Entities' }).click();
    await expect(page.getByRole('tab', { name: 'Entities', selected: true })).toBeVisible();

    // Select all entities in the list (ie the malware we just created)
    await dataTable.getCheckAll().click();

    // Launch a background task to add a label on the malware
    await taskPopup.launchAddLabel(labelToApply);

    // Need to wait after click on "Launch" that the popup goes away.
    await expect(taskPopup.getPage().getByText('Launch a background task')).not.toBeVisible({ timeout: 3000 });

    // Wait for the background task to complete
    await checkBackgroundTasksCompletion(request);

    // Check the update has been done only on the malware
    await expect(dataTable.getNumberElements(1)).toBeVisible();

    // Filter by the applied label and check the malware is still in the list
    await filter.addFilter('Label', labelToApply);
    await expect(dataTable.getNumberElements(1)).toBeVisible();
    await expect(Drafts.getEntityInList(malwareName)).toBeVisible();
  });
});

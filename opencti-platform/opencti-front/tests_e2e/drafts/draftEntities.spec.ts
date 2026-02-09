import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import DataTablePage from '../model/DataTable.pageModel';
import TaskPopup from '../model/taskPopup.pageModel';
import { checkBackgroundTasksCompletion } from '../utils/backgroundTaskCheck-utils';
import { v4 as uuid } from 'uuid';

test.describe('Drafts - Entities and background tasks', { tag: ['@ce'] }, () => {
  const draftName = `Draft E2E - ${Date.now()}`;
  const malwareName = `malware in draft- ${uuid()}`;
  test('should create a draft, add a malware entity, and verify its presence', async ({ page }) => {
    const Drafts = new DraftsPage(page);
    const taskPopup = new TaskPopup(page);
    const dataTable = new DataTablePage(page);

    // navigate in the drafts list
    await Drafts.navigate();

    // create a new draft
    await Drafts.createDraft({ name: draftName });
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // enter in the draft
    await page.getByText(draftName).click();

    // check we are in the 'entities' tab
    await expect(page.getByRole('tab', { name: /Entities/i, selected: true })).toBeVisible();

    // add a malware in the draft
    await Drafts.addEntityToDraft({
      type: 'Malware',
      name: malwareName,
    });

    // check the malware is in the list
    await expect(Drafts.getEntityInList(malwareName)).toBeVisible();

    // Select all entities in the list
    await dataTable.getCheckAll().click();
    // Click the "remove from draft" icon in the toolbar
    await taskPopup.launchRemoveFromDraft();

    // Wait for the background task to complete
    await checkBackgroundTasksCompletion(page.request);

    // Check that the malware is no longer in the list
    await expect(Drafts.getEntityInList(malwareName)).not.toBeVisible();

    // TODO check other malwares have not been deleted
  });
});

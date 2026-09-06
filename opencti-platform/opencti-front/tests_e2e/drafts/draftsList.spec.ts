import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import SearchPageModel from 'tests_e2e/model/search.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import { restoreAdminSession } from '../restoreAdminSession';

test.describe('Drafts list', { tag: ['@ce', '@workflow'] }, () => {
  test('should list, search, and delete manually-created drafts', async ({ page }) => {
    const timestamp = Date.now();
    const alphaName = `Drafts List E2E Alpha - ${timestamp}`;
    const betaName = `Drafts List E2E Beta - ${timestamp}`;

    const Drafts = new DraftsPage(page);
    const Search = new SearchPageModel(page);

    // Unlike its sibling Threat Advisory specs (which always explicitly log in via
    // loginAs/openDraft), this test previously assumed it inherited a valid admin session
    // from the preceding 'form intake setup' project. Explicitly (re)restoring the admin
    // session here removes that fragile cross-project assumption.
    await restoreAdminSession(page);

    await Drafts.navigate();
    await Drafts.createDraft({ name: alphaName, authorizedMembers: [] });
    await expect(Drafts.getDraft(alphaName)).toBeVisible();

    await Drafts.createDraft({ name: betaName, authorizedMembers: [] });
    await expect(Drafts.getDraft(betaName)).toBeVisible();

    await Search.addExactSearch(alphaName);
    await expect(Drafts.getDraft(alphaName)).toBeVisible();
    await expect(Drafts.getDraft(betaName)).not.toBeVisible();

    // Clearing the search (fresh navigation) restores the full list.
    await Search.clearSearch();
    await Drafts.navigate();
    await expect(Drafts.getDraft(betaName)).toBeVisible();

    await Drafts.deleteDraft(alphaName);
    await Drafts.deleteDraft(betaName);
    await page.reload();
    await expect(Drafts.getDraft(alphaName)).not.toBeVisible();
    await expect(Drafts.getDraft(betaName)).not.toBeVisible();
  });
});

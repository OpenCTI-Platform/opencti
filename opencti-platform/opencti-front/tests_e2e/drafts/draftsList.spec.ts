import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import SearchPageModel from 'tests_e2e/model/search.pageModel';
import { setTimeout } from 'node:timers/promises';
import { expect, test } from '../fixtures/baseFixtures';
import { restoreAdminSession } from '../restoreAdminSession';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';

// Runs in the plain 'chromium' project, not after the Threat Advisory setup: once that workflow
// exists, every draft gets its NEW-status authorized members (OrgA only), and the admin's drafts
// list stops showing them, so a draft created here would never be listed.
test.describe('Drafts list', { tag: ['@ce'] }, () => {
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

    // Retry the search itself (not just re-poll the same result) - under CI resource
    // contention the search query can occasionally return before the freshly created draft
    // is reflected, and re-pressing Enter re-issues it rather than waiting out a dead end.
    await expect(async () => {
      await Search.addExactSearch(alphaName);
      await expect(Drafts.getDraft(alphaName)).toBeVisible({ timeout: 5000 });
    }).toPass({ timeout: 60000, intervals: [2000, 5000, 10000] });
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

  test('should exit an existing draft after a delayed login', { tag: '@mutation' }, async ({ page }) => {
    const draftName = `Draft Session E2E - ${crypto.randomUUID()}`;
    const drafts = new DraftsPage(page);
    const toolbar = new DraftToolbarPageModel(page);
    const loginForm = new LoginFormPageModel(page);
    const topBar = new TopMenuProfilePage(page);

    await restoreAdminSession(page);
    await toolbar.exitDraftIfPresent();
    await drafts.createDraft({ name: draftName, authorizedMembers: [] });
    await drafts.openDraft(draftName);
    await toolbar.assertHasAccess();
    await topBar.logout();
    await expect(loginForm.getPage()).toBeVisible();

    // Reproduce CI's slow post-login bootstrap and independently delayed draft toolbar.
    await page.route('**/graphql', async (route) => {
      const operation = route.request().postDataJSON()?.id;
      if (operation === 'RootPrivateQuery' || operation === 'DraftToolbarQuery') {
        await setTimeout(8000);
      }
      await route.fallback();
    });

    try {
      await loginForm.login();
      expect(await topBar.getMenuProfile().isVisible()).toBe(true);
      await toolbar.exitDraftIfPresent();
      await expect(drafts.getPage()).toBeVisible();
      await expect(toolbar.getToolbar()).toBeHidden();
    } finally {
      await page.unrouteAll({ behavior: 'wait' });
      await restoreAdminSession(page);
      await toolbar.exitDraftIfPresent();
      await drafts.navigate();
      await drafts.deleteDraft(draftName);
    }
  });
});

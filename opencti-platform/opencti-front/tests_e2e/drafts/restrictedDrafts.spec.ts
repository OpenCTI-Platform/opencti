import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import RestrictionsPage from 'tests_e2e/model/restrictions.pageModel';
import { expect, test } from '../fixtures/baseFixtures';

test.describe('Restricted Drafts', () => {
  test('should allow to remove restrictions on a draft', { tag: ['@ce'] }, async ({ page }) => {
    const draftName = `Restricted Draft E2E - ${Date.now()}`;

    // create a restricted draft
    const Drafts = new DraftsPage(page);
    const Restrictions = new RestrictionsPage(page);

    await Drafts.navigate();
    await Drafts.createDraft({
      name: draftName,
      authorizedMembers: [
        { name: 'Jean Michel', permission: 'can view' },
      ],
    });
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // remove all restrictions on the created draft
    await Restrictions.navigateToRestrictedDrafts();
    await expect(Restrictions.getDraft(draftName)).toBeVisible();

    // remove restrictions on the draft
    await Restrictions.removeRestrictionsOnDraft(draftName);
    await page.reload();
    await expect(Restrictions.getDraft(draftName)).not.toBeVisible();

    // verify the draft no longer appears in the restricted drafts list
    await Drafts.navigate();
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // clean up by deleting the created draft
    await Drafts.deleteDraft(draftName);
    await page.reload();
    await expect(Drafts.getDraft(draftName)).not.toBeVisible();
  });
});

import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import RestrictionsPage from 'tests_e2e/model/restrictions.pageModel';
import { expect, test } from '../fixtures/baseFixtures';

test.describe('Draft Review Tab Navigation', { tag: ['@ce'] }, () => {
  test('should navigate to the draft review tab', async ({ page }) => {
    const draftName = `Draft Review E2E - ${Date.now()}`;
    const Drafts = new DraftsPage(page);

    // 1. Create a temporary draft workspace
    await Drafts.navigate();
    await Drafts.createDraft({
      name: draftName,
      authorizedMembers: [],
    });
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // 2. Navigate into the draft workspace by clicking the row
    await Drafts.getDraft(draftName).click();
    await expect(page).toHaveURL(/\/dashboard\/data\/import\/draft\//);

    // 3. Locate the "Review" tab and click it
    const reviewTab = page.getByRole('tab', { name: /Review/i });
    await expect(reviewTab).toBeVisible();
    await reviewTab.click();

    // 4. Verify successful redirection to the review subroute
    await expect(page).toHaveURL(/\/dashboard\/data\/import\/draft\/.*\/review/);

    // 5. Clean up by exiting the draft workspace and deleting it
    const exitDraftButton = page.getByRole('button', { name: 'Exit draft' });
    await expect(exitDraftButton).toBeVisible();
    await exitDraftButton.click();
    await expect(page).toHaveURL(/\/dashboard\/data\/import\/draft$/);

    const draftRow = Drafts.getDraft(draftName);
    await draftRow.getByLabel('Draft popover of actions').click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    // Verify deletion completed
    await expect(Drafts.getDraft(draftName)).toBeHidden({ timeout: 5000 });
  });
});

test.describe('Restricted Drafts', { tag: ['@ce'] }, () => {
  test('should allow to remove restrictions on a draft', async ({ page }) => {
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
    await expect(Restrictions.getDraft(draftName)).toBeHidden({ timeout: 5000 });

    // verify the draft no longer appears in the restricted drafts list
    await Drafts.navigate();
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // clean up by deleting the created draft
    await Drafts.deleteDraft(draftName);
    await expect(Drafts.getDraft(draftName)).toBeHidden({ timeout: 5000 });
  });
});

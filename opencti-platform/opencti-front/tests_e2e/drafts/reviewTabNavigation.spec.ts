import DraftsPage from 'tests_e2e/model/drafts.pageModel';
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

    // 5. Clean up by deleting the created draft
    await Drafts.navigate();
    const draftRow = Drafts.getDraft(draftName);
    await draftRow.getByLabel('Draft popover of actions').click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    // Verify deletion completed
    await page.reload();
    await expect(Drafts.getDraft(draftName)).not.toBeVisible();
  });
});

/**
 * "Submission of a Threat Advisory - Rejection by ManagerOrgC"
 * (`workflow-e2e-product-test-plan.md`). Starts a fresh draft and fast-forwards it to
 * ORGC MANAGER REVIEW (equivalent to happy-flow steps 1-13), instead of replaying the full happy path.
 */
import { test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { advanceDraftToStatus, createThreatAdvisoryDraft, openDraft, USERS } from './threatAdvisoryDraftHelpers';

test('Threat Advisory - rejection by ManagerOrgC', { tag: ['@ee', '@group1'] }, async ({ page }) => {
  test.setTimeout(120000);

  const toolbar = new DraftToolbarPageModel(page);

  const reportName = `Threat Advisory Rejection ManagerOrgC E2E - ${crypto.randomUUID()}`;
  const draftId = await createThreatAdvisoryDraft(page, reportName);
  await advanceDraftToStatus(page, draftId, 'ORGC MANAGER REVIEW');

  await openDraft(page, draftId, USERS.managerOrgC);

  await test.step('Step 1: selecting "Reject" requires a comment before confirming', async () => {
    await toolbar.openTransition('Reject');
    await toolbar.assertCommentConfirmDisabled();
  });

  await test.step('Step 2: clicking Cancel applies no new status', async () => {
    await toolbar.fillCommentStep({ cancel: true });
    await toolbar.assertStatus('ORGC MANAGER REVIEW');
  });

  await test.step('Step 3: "Reject" + comment moves the draft back to NEW', async () => {
    await toolbar.openTransition('Reject');
    await toolbar.fillCommentStep({ comment: 'Rejected by ManagerOrgC E2E test' });
    await toolbar.assertStatus('NEW');
  });

  // (step 4 skipped in the source numbering)

  await test.step('Step 6: ManagerOrgC refreshes right after the transition, loses all access', async () => {
    await page.reload({ waitUntil: 'domcontentloaded' });
    await toolbar.assertNoAccess();
  });

  await test.step('Step 5: AnalystOrgA sees the rejection comment', async () => {
    await openDraft(page, draftId, USERS.analystOrgA);
    await toolbar.assertLastCommentVisible('Rejected by ManagerOrgC E2E test');
  });
});

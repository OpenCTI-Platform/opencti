/**
 * "Submission of a Threat Advisory - rejection by ManagerOrg"
 * (`workflow-e2e-product-test-plan.md`). Starts a fresh draft and fast-forwards it to
 * MO MANAGER REVIEW (equivalent to happy-flow steps 1-7), instead of replaying the full happy path.
 */
import { expect, test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import DraftOverviewPageModel from '../model/drafts/draftOverview.pageModel';
import { advanceDraftToStatus, createThreatAdvisoryDraft, openDraft, USERS } from './threatAdvisoryDraftHelpers';

test('Threat Advisory - rejection by ManagerOrgA', { tag: ['@ee', '@group1'] }, async ({ page }) => {
  test.setTimeout(180000);

  const toolbar = new DraftToolbarPageModel(page);
  const overview = new DraftOverviewPageModel(page);

  const reportName = `Threat Advisory Rejection ManagerOrgA E2E - ${crypto.randomUUID()}`;
  const draftId = await createThreatAdvisoryDraft(page, reportName);
  await advanceDraftToStatus(page, draftId, 'MO MANAGER REVIEW');

  await test.step('Step 1: ManagerOrgA accesses the draft, can edit, sees REJECT + "Send to OrgC for review"', async () => {
    await openDraft(page, draftId, USERS.managerOrgA, 'overview');
    await overview.assertCanEdit();
    await toolbar.assertStatus('MO MANAGER REVIEW');
    await expect(toolbar.getTransitionsActions().getByText('Reject')).toBeVisible();
    await expect(toolbar.getTransitionsActions().getByText('Send to OrgC for review')).toBeVisible();
  });

  await test.step('Step 2: selecting "Reject" requires a comment before confirming', async () => {
    await toolbar.openTransition('Reject');
    await toolbar.assertCommentConfirmDisabled();
  });

  await test.step('Step 3: clicking Cancel applies no new status', async () => {
    await toolbar.fillCommentStep({ cancel: true });
    await toolbar.assertStatus('MO MANAGER REVIEW');
  });

  await test.step('Step 4: "Reject" + comment moves the draft back to NEW', async () => {
    await toolbar.openTransition('Reject');
    await toolbar.fillCommentStep({ comment: 'Rejected by ManagerOrgA E2E test' });
    await toolbar.assertStatus('NEW');
  });

  await test.step('Step 5: AnalystOrgA sees the rejection comment', async () => {
    await openDraft(page, draftId, USERS.analystOrgA);
    await toolbar.assertLastCommentVisible('Rejected by ManagerOrgA E2E test');
  });
});

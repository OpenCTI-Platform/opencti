/**
 * "Submission of a Threat Advisory - issue with OrgSharing"
 * (`workflow-e2e-product-test-plan.md`). Starts a fresh draft and fast-forwards it to
 * ORGC MANAGER REVIEW (equivalent to happy-flow steps 1-13), instead of replaying the full happy path.
 *
 * There is no real, deterministic way to make the "SHARE TO ORG" background task genuinely fail
 * through valid user input (picking a real, existing org will genuinely succeed) - instead, the
 * `DraftToolbarQuery` polling response (`DraftToolbar.tsx`) is intercepted and its
 * `workflowInstance.pendingStatus`/`pendingError` fields are rewritten to simulate a failure,
 * to deterministically drive the frontend into its error/retry UX (which is what this scenario
 * is really testing). There is also no distinct "Retry" button in the product - the real flow is
 * a bypass-only "Clear" button (unlocks the errored transition) followed by re-triggering
 * "SHARE TO ORG" (see `workflow-e2e-plan.md`'s Phase 0 research spike (b)).
 */
import { test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { advanceDraftToStatus, createThreatAdvisoryDraft, openDraft, USERS } from './threatAdvisoryDraftHelpers';

/** Recursively finds a `workflowInstance`-shaped object with `pendingStatus: 'pending'` and
 * rewrites it to `'error'`, regardless of exactly where the `WorkflowStatus_data` fragment is
 * nested in the payload. Only rewrites genuinely in-flight transitions - leaving a `null`/absent
 * `pendingStatus` untouched, otherwise every poll (including before any transition is triggered)
 * would be forced into the error state and hide the transition buttons entirely. */
const injectPendingError = (value: unknown): void => {
  if (!value || typeof value !== 'object') return;
  const obj = value as Record<string, unknown>;
  if (obj.pendingStatus === 'pending') {
    obj.pendingStatus = 'error';
    obj.pendingError = 'Simulated E2E failure (route interception)';
  }
  for (const key of Object.keys(obj)) {
    injectPendingError(obj[key]);
  }
};

test('Threat Advisory - org-sharing failure + retry', { tag: ['@ee', '@group1'] }, async ({ page }) => {
  test.setTimeout(120000);

  const toolbar = new DraftToolbarPageModel(page);

  const reportName = `Threat Advisory OrgSharing E2E - ${crypto.randomUUID()}`;
  const draftId = await createThreatAdvisoryDraft(page, reportName);
  await advanceDraftToStatus(page, draftId, 'ORGC MANAGER REVIEW');
  await openDraft(page, draftId, USERS.managerOrgC);

  let simulateFailure = true;
  await page.route('**/graphql', async (route) => {
    const postData = route.request().postData() ?? '';
    if (!simulateFailure || !postData.includes('DraftToolbarQuery')) {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const body = await response.json();
    injectPendingError(body);
    await route.fulfill({ response, json: body });
  });

  await test.step('Step 1: ManagerOrgC shares to OrgB but the background task fails: error shown, status unchanged, Retry (Clear) available', async () => {
    await toolbar.openTransition('SHARE TO ORG');
    await toolbar.fillOrgPickerStep({ share: ['OrgB'] });
    await toolbar.assertTransitionError();
    await toolbar.assertStatus('ORGC MANAGER REVIEW');
  });

  await test.step('Step 17 (source numbering, really step 2): clicking Clear then retriggering "SHARE TO ORG" succeeds', async () => {
    simulateFailure = false;
    await toolbar.getClearButton().click();
    await toolbar.openTransition('SHARE TO ORG');
    await toolbar.fillOrgPickerStep({ share: ['OrgB'] });
    await toolbar.assertStatus('READY FOR VALIDATION');
  });

  await page.unroute('**/graphql');
});

/**
 * "Submission of a Threat Advisory - issue with OrgSharing" (`workflow-e2e-product-test-plan.md`).
 * Fast-forwards a fresh draft to ORGC MANAGER REVIEW (happy-flow steps 1-13).
 *
 * The "SHARE TO ORG" background task can't be made to genuinely fail through valid user input, so
 * the `DraftToolbarQuery` polling response is intercepted and rewritten to simulate a failure and
 * drive the frontend into its error/retry UX. There is no distinct "Retry" button - the real flow
 * is a bypass-only "Clear" button followed by re-triggering "SHARE TO ORG".
 */
import { test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { advanceDraftToStatus, createThreatAdvisoryDraft, openDraft, USERS } from './threatAdvisoryDraftHelpers';

/** Rewrites a genuinely in-flight (`pendingStatus: 'pending'`) `workflowInstance` to `'error'`; leaves other values untouched so pre-transition polls still render normally. */
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

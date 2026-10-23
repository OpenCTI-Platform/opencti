/**
 * "Submission of a Threat Advisory - issue with OrgSharing" (`workflow-e2e-product-test-plan.md`).
 * Fast-forwards a fresh draft to ORGC MANAGER REVIEW (happy-flow steps 1-13).
 *
 * The "SHARE TO ORG" background task can't be made to fail through the wizard, and sharing with an
 * unknown organization does not fail it either (the backend skips it and the transition completes).
 * So, while `simulateFailure` is set, the `triggerWorkflowEvent` mutation never reaches the backend
 * (no task runs, nothing can finish before the toolbar polls) and the toolbar queries report the
 * instance as failed. This drives the frontend into its error/retry UX deterministically.
 * There is no distinct "Retry" button - the real flow is a bypass-only "Clear" button (so an admin
 * clicks it; a real mutation, valid with nothing pending) followed by ManagerOrgC re-triggering
 * "SHARE TO ORG" for real.
 */
import { test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { advanceDraftToStatus, createThreatAdvisoryDraft, openDraft, USERS } from './threatAdvisoryDraftHelpers';

const ADMIN = { email: 'admin@opencti.io', password: 'admin' };

/** Reports every `workflowInstance` found in a toolbar response as failed on "SHARE TO ORG". */
const injectPendingError = (value: unknown): void => {
  if (!value || typeof value !== 'object') return;
  const obj = value as Record<string, unknown>;
  const instance = obj.workflowInstance as Record<string, unknown> | null | undefined;
  if (instance && typeof instance === 'object') {
    instance.pendingStatus = 'error';
    instance.pendingError = 'Simulated E2E failure (route interception)';
    instance.pendingTransition = {
      event: 'SHARE TO ORG',
      toState: instance.currentState,
      triggeredAt: new Date().toISOString(),
      syncActions: [],
      asyncActions: [],
    };
  }
  for (const key of Object.keys(obj)) {
    injectPendingError(obj[key]);
  }
};

test('Threat Advisory - org-sharing failure + retry', { tag: ['@ee', '@workflow'] }, async ({ page }) => {
  test.setTimeout(300000); // Includes setup transitions and five persona logins before testing sharing.

  const toolbar = new DraftToolbarPageModel(page);

  const reportName = `Threat Advisory OrgSharing E2E - ${crypto.randomUUID()}`;
  const draftId = await createThreatAdvisoryDraft(page, reportName);
  await advanceDraftToStatus(page, draftId, 'ORGC MANAGER REVIEW');
  await openDraft(page, draftId, USERS.managerOrgC);

  let simulateFailure = true;
  let triggered = false; // toolbar queries only report the failure once the transition was fired
  await page.route('**/graphql', async (route) => {
    const postData = route.request().postData() ?? '';
    if (!simulateFailure) {
      await route.fallback();
      return;
    }
    if (postData.includes('clearWorkflowPendingState')) {
      // The real Clear ends the simulated failure: every later toolbar query shows the real state.
      simulateFailure = false;
      await route.fallback();
      return;
    }
    if (postData.includes('triggerWorkflowEvent')) {
      triggered = true;
      await route.fulfill({ json: { data: { triggerWorkflowEvent: { success: true, reason: null, newState: null, executionStatus: 'pending', instance: null, entity: null } } } });
      return;
    }
    if (!triggered || !postData.includes('DraftToolbarQuery')) {
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
    await toolbar.fillWizard({ share: ['OrgB'] });
    await toolbar.assertTransitionError();
    await toolbar.assertStatus('ORGC MANAGER REVIEW');
  });

  await test.step('Step 17 (source numbering, really step 2): an admin clears the failed transition, then ManagerOrgC retriggering "SHARE TO ORG" succeeds', async () => {
    // "Clear" is bypass-only (`WorkflowTransitions.tsx`), ManagerOrgC does not see it.
    await openDraft(page, draftId, ADMIN);
    await toolbar.getClearButton().click();
    await toolbar.assertNoTransitionError();
    // Opening the draft put the admin in its draft context, which sticks to the shared admin user.
    await toolbar.exitDraftIfPresent();
    await openDraft(page, draftId, USERS.managerOrgC);
    await toolbar.openTransition('SHARE TO ORG');
    await toolbar.fillWizard({ share: ['OrgB'] });
    await toolbar.assertStatus('READY FOR VALIDATION');
  });

  await page.unroute('**/graphql');
});

/**
 * "Submission of a Threat Advisory - issue with OrgSharing" (`workflow-e2e-product-test-plan.md`).
 * Fast-forwards a fresh draft to ORGC MANAGER REVIEW (happy-flow steps 1-13).
 *
 * The "SHARE TO ORG" background task can't be made to fail through the wizard (it only offers
 * existing organizations), so the `triggerWorkflowEvent` request is rewritten to share with an
 * organization that does not exist. The backend then runs a real task that really fails, which
 * is deterministic: nothing is faked in a response, and no successful task is left running.
 * There is no distinct "Retry" button - the real flow is a bypass-only "Clear" button followed
 * by re-triggering "SHARE TO ORG".
 */
import { test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { advanceDraftToStatus, createThreatAdvisoryDraft, openDraft, USERS } from './threatAdvisoryDraftHelpers';

const UNKNOWN_ORGANIZATION_ID = '00000000-0000-4000-8000-000000000000';

test('Threat Advisory - org-sharing failure + retry', { tag: ['@ee', '@workflow'] }, async ({ page }) => {
  test.setTimeout(300000); // Includes setup transitions and five persona logins before testing sharing.

  const toolbar = new DraftToolbarPageModel(page);

  const reportName = `Threat Advisory OrgSharing E2E - ${crypto.randomUUID()}`;
  const draftId = await createThreatAdvisoryDraft(page, reportName);
  await advanceDraftToStatus(page, draftId, 'ORGC MANAGER REVIEW');
  await openDraft(page, draftId, USERS.managerOrgC);

  let shareToUnknownOrganization = true;
  await page.route('**/graphql', async (route) => {
    const body = route.request().postDataJSON();
    if (!shareToUnknownOrganization || !body?.query?.includes('triggerWorkflowEvent')) {
      await route.fallback();
      return;
    }
    body.variables.runtimeParams.shareOrganizationIds = [UNKNOWN_ORGANIZATION_ID];
    await route.continue({ postData: JSON.stringify(body) });
  });

  await test.step('Step 1: ManagerOrgC shares to OrgB but the background task fails: error shown, status unchanged, Retry (Clear) available', async () => {
    await toolbar.openTransition('SHARE TO ORG');
    await toolbar.fillWizard({ share: ['OrgB'] });
    await toolbar.assertTransitionError();
    await toolbar.assertStatus('ORGC MANAGER REVIEW');
  });

  await test.step('Step 17 (source numbering, really step 2): clicking Clear then retriggering "SHARE TO ORG" succeeds', async () => {
    shareToUnknownOrganization = false;
    await toolbar.getClearButton().click();
    await toolbar.openTransition('SHARE TO ORG');
    await toolbar.fillWizard({ share: ['OrgB'] });
    await toolbar.assertStatus('READY FOR VALIDATION');
  });

  await page.unroute('**/graphql');
});

import { Page } from '@playwright/test';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import ImportFilesDialogPageModel from '../model/formIntake/importFilesDialog.pageModel';
import FormIntakeFillPageModel from '../model/formIntake/formIntakeFill.pageModel';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';

/**
 * Shared fixtures/helpers for the Threat Advisory rejection & org-sharing-retry variant specs
 * (`workflow-e2e-product-test-plan.md`'s "Scenario:" sections) - each variant starts from a
 * fresh draft fast-forwarded to the status it assumes, rather than replaying the full UI happy
 * path from `threatAdvisoryHappyFlow.spec.ts`.
 */
export const USERS = {
  analystOrgA: { email: 'analystorga@filigran.test', password: 'analystorga' },
  managerOrgA: { email: 'managerorga@filigran.test', password: 'managerorga' },
  analystOrgC: { email: 'analystorgc@filigran.test', password: 'analystorgc' },
  managerOrgC: { email: 'managerorgc@filigran.test', password: 'managerorgc' },
};

export type TestUser = typeof USERS[keyof typeof USERS];

export const loginAs = async (page: Page, user: TestUser) => {
  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);
  const toolbar = new DraftToolbarPageModel(page);
  await topBar.logout();
  await loginForm.login(user.email, user.password);
  // A previous, interrupted test run may have left this user stuck in a draft context.
  await toolbar.exitDraftIfPresent();
};

/** Report is a Container-type entity, shown under the "Containers" tab, not "Entities". */
export const openDraft = async (page: Page, draftId: string, user: TestUser, tab: 'containers' | 'overview' = 'containers') => {
  await loginAs(page, user);
  await page.goto(`/dashboard/data/import/draft/${draftId}/${tab}`, { waitUntil: 'domcontentloaded' });
};

/** Submits a fresh Threat Advisory form as AnalystOrgA (status NEW) and returns the draft id. */
export const createThreatAdvisoryDraft = async (page: Page, reportName: string): Promise<string> => {
  await page.goto('/');
  await loginAs(page, USERS.analystOrgA);
  const importDialog = new ImportFilesDialogPageModel(page);
  const formFill = new FormIntakeFillPageModel(page, importDialog.getRoot());
  await importDialog.open();
  await importDialog.selectFormMode();
  await importDialog.selectForm('Threat Advisories');
  await formFill.assertLoaded();
  await formFill.fillTextField('Name', reportName);
  await formFill.selectAuthor('OrgA');
  await formFill.submit();
  return formFill.waitForDraftCreated();
};

export type DraftStatus = 'MO MANAGER REVIEW' | 'ORGC ANALYST REVIEW' | 'ORGC MANAGER REVIEW';

/**
 * Fast-forwards a fresh NEW-status draft through the minimal transitions needed to reach the
 * given target status, using the correct persona for each hop (mirrors happy-flow steps 5/8/11).
 */
export const advanceDraftToStatus = async (page: Page, draftId: string, targetStatus: DraftStatus) => {
  const toolbar = new DraftToolbarPageModel(page);

  await openDraft(page, draftId, USERS.analystOrgA);
  await toolbar.openTransition('Request MO manager review');
  if (targetStatus === 'MO MANAGER REVIEW') return;

  await openDraft(page, draftId, USERS.managerOrgA);
  await toolbar.openTransition('Send to OrgC for review');
  if (targetStatus === 'ORGC ANALYST REVIEW') return;

  await openDraft(page, draftId, USERS.analystOrgC);
  await toolbar.openTransition('SEND TO ORGC MANAGER');
  // targetStatus === 'ORGC MANAGER REVIEW'
};

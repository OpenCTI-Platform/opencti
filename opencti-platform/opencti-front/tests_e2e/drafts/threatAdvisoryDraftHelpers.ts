import { Browser, Page, TestInfo } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import ImportFilesDialogPageModel from '../model/formIntake/importFilesDialog.pageModel';
import FormIntakeFillPageModel from '../model/formIntake/formIntakeFill.pageModel';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { PERSONAS } from '../dataForTesting/threatAdvisory.data';

/**
 * Shared helpers for the Threat Advisory rejection & org-sharing-retry specs, which fast-forward a
 * fresh draft to the status they assume instead of replaying `threatAdvisoryHappyFlow.spec.ts`.
 */
export const USERS = PERSONAS;

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

/**
 * A goto can be aborted by a navigation the app starts itself (e.g. a reload after login), or hang
 * for minutes without ever committing under load: bound each attempt (a goto has no timeout of its
 * own, so a retry loop around it could never fire) and retry it.
 */
export const gotoDraft = (page: Page, draftId: string, tab: 'containers' | 'overview' = 'containers') => expect(async () => {
  await page.goto(`/dashboard/data/import/draft/${draftId}/${tab}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
}).toPass({ timeout: 120000, intervals: [1000] });

/**
 * Logs in as `user` and opens the draft. Report is a Container-type entity, shown under the
 * "Containers" tab, not "Entities". The whole sequence is redone when the draft page does not settle
 * (toolbar, or the no-access page): under CI load the app can stay on a blank page or its spinner,
 * and waiting longer on that page never helps.
 */
export const openDraft = async (page: Page, draftId: string, user: TestUser, tab: 'containers' | 'overview' = 'containers') => {
  const toolbar = new DraftToolbarPageModel(page);
  await expect(async () => {
    await loginAs(page, user);
    await gotoDraft(page, draftId, tab);
    await expect(toolbar.getToolbar().or(toolbar.getNoAccessMessage())).toBeVisible({ timeout: 30000 });
  }).toPass({ timeout: 300000, intervals: [1000] });
};

/** Submits the Threat Advisories form through the UI, in a page already logged in as a submitter, and returns the draft id. */
export const submitThreatAdvisoryForm = async (page: Page, reportName: string): Promise<string> => {
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

/** Submits a fresh Threat Advisory form as AnalystOrgA (status NEW) and returns the draft id. */
export const createThreatAdvisoryDraft = async (page: Page, reportName: string): Promise<string> => {
  await page.goto('/');
  await loginAs(page, USERS.analystOrgA);
  return submitThreatAdvisoryForm(page, reportName);
};

/**
 * Opens the draft page in a page that is already logged in, and waits for it to settle (toolbar,
 * or the no-access page). Report is a Container-type entity, shown under the "Containers" tab.
 */
export const openDraftPage = async (page: Page, draftId: string, tab: 'containers' | 'overview' = 'containers') => {
  const toolbar = new DraftToolbarPageModel(page);
  await expect(async () => {
    await gotoDraft(page, draftId, tab);
    await expect(toolbar.getToolbar().or(toolbar.getNoAccessMessage())).toBeVisible({ timeout: 30000 });
  }).toPass({ timeout: 180000, intervals: [1000] });
};

/**
 * Runs `body` in a fresh browser context logged in as `user`: its own cookies, its own renderer, and
 * no logout (a logout destroys the session the next step would otherwise have to rebuild). The test
 * runner traces the context like any other; a screenshot of the persona is kept when `body` throws.
 */
export const asPersona = async <T>(browser: Browser, testInfo: TestInfo, user: TestUser, body: (page: Page) => Promise<T>): Promise<T> => {
  const { baseURL, viewport } = testInfo.project.use;
  const context = await browser.newContext({ baseURL, viewport, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const name = user.email.split('@')[0];
  try {
    await expect(async () => {
      // Each attempt starts logged out, so the login form is shown whatever the previous attempt got done.
      await context.clearCookies();
      await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 30000 });
      await new LoginFormPageModel(page).login(user.email, user.password);
      // A previous run may have left this user stuck in a draft context.
      await new DraftToolbarPageModel(page).exitDraftIfPresent();
    }).toPass({ timeout: 180000, intervals: [1000] });
    return await body(page);
  } catch (error) {
    await page.screenshot({ path: testInfo.outputPath(`${name}-failure.png`) }).catch(() => {});
    throw error;
  } finally {
    await context.close();
  }
};

export type DraftStatus = 'MO MANAGER REVIEW' | 'ORGC ANALYST REVIEW' | 'ORGC MANAGER REVIEW';

/**
 * Fast-forwards a fresh NEW-status draft to the given target status, using the correct persona
 * for each hop (mirrors happy-flow steps 5/8/11). Each transition completes asynchronously, so
 * the resulting status is awaited before switching personas - otherwise the next persona can
 * load the draft before it applies, and see stale transitions for the previous status instead.
 */
export const advanceDraftToStatus = async (page: Page, draftId: string, targetStatus: DraftStatus) => {
  const toolbar = new DraftToolbarPageModel(page);

  await openDraft(page, draftId, USERS.analystOrgA);
  await toolbar.openTransition('Request MO manager review');
  await toolbar.assertStatus('MO MANAGER REVIEW');
  if (targetStatus === 'MO MANAGER REVIEW') return;

  await openDraft(page, draftId, USERS.managerOrgA);
  await toolbar.openTransition('Send to OrgC for review');
  await toolbar.assertStatus('ORGC ANALYST REVIEW');
  if (targetStatus === 'ORGC ANALYST REVIEW') return;

  await openDraft(page, draftId, USERS.analystOrgC);
  await toolbar.openTransition('SEND TO ORGC MANAGER');
  await toolbar.assertStatus('ORGC MANAGER REVIEW');
  // targetStatus === 'ORGC MANAGER REVIEW'
};

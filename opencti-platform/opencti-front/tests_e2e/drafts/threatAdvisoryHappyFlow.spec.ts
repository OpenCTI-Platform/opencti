/**
 * Authoritative "happy flow" scenario (24 steps, `workflow-e2e-product-test-plan.md`): a Threat
 * Advisory Report is submitted as a draft, moved through every workflow status by the correct
 * persona, shared to OrgB, validated into a real Report, then its final authorized members are
 * checked from every persona's point of view.
 *
 * Split into four independent phase tests, so a flaky browser only costs one phase (Playwright
 * retries the failed test alone, and the phases are not tied to one another). Each phase builds its
 * starting state through the API, as the persona who would have produced it, and tests only its own
 * transitions and visibility checks in the UI. Every persona gets a fresh browser context.
 *
 *   Phase 1 - submission and visibility:   steps 1-4
 *   Phase 2 - MO manager review:           steps 5-9
 *   Phase 3 - OrgC review:                 steps 10-13
 *   Phase 4 - sharing and validation:      steps 14-17, then the Report access checks 19-24
 *
 * Step 18 (backend/playbook): the "Report created" playbook sets the final authorized members -
 * awaited through the API before the access checks of phase 4.
 *
 * Depends on the fixtures built by `workflow/threatAdvisoryWorkflowSetup.spec.ts` and
 * `formIntake/threatAdvisorySetup.spec.ts`, and the test-data matrix seeded by the `'init data'` project.
 */
import { expect, test } from '../fixtures/baseFixtures';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import DraftOverviewPageModel from '../model/drafts/draftOverview.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import { advanceDraftViaApi, submitThreatAdvisoryDraftViaApi, waitForReportAccessApplied } from '../dataForTesting/threatAdvisory.data';
import { asPersona, gotoDraft, openDraftPage, submitThreatAdvisoryForm, USERS } from './threatAdvisoryDraftHelpers';

const newReportName = () => `Threat Advisory E2E - ${crypto.randomUUID()}`;

test('Threat Advisory happy flow - phase 1: submission and visibility (steps 1-4)', { tag: ['@ee', '@workflow'] }, async ({ browser }, testInfo) => {
  test.setTimeout(300000);
  const reportName = newReportName();
  let draftId = '';

  await test.step('Step 1: AnalystOrgA submits the Threat Advisory form as a draft (status New)', async () => {
    await asPersona(browser, testInfo, USERS.analystOrgA, async (page) => {
      draftId = await submitThreatAdvisoryForm(page, reportName);
      await new DraftToolbarPageModel(page).assertStatus('NEW');
    });
  });

  await test.step('Step 2: AnalystOrgC cannot see the draft', async () => {
    await asPersona(browser, testInfo, USERS.analystOrgC, async (page) => {
      await openDraftPage(page, draftId);
      await new DraftToolbarPageModel(page).assertNoAccess();
    });
  });

  await test.step('Step 3: ManagerOrgB cannot see the draft', async () => {
    await asPersona(browser, testInfo, USERS.managerOrgB, async (page) => {
      await openDraftPage(page, draftId);
      await new DraftToolbarPageModel(page).assertNoAccess();
    });
  });

  await test.step('Step 4: ManagerOrgA can view but cannot transition (view-only)', async () => {
    await asPersona(browser, testInfo, USERS.managerOrgA, async (page) => {
      await openDraftPage(page, draftId);
      await new DraftOverviewPageModel(page).assertName(reportName);
      await new DraftToolbarPageModel(page).assertNoTransitions();
    });
  });
});

test('Threat Advisory happy flow - phase 2: MO manager review (steps 5-9)', { tag: ['@ee', '@workflow'] }, async ({ browser, playwright, baseURL }, testInfo) => {
  test.setTimeout(300000);
  const draftId = await submitThreatAdvisoryDraftViaApi(playwright, baseURL!, newReportName());

  await asPersona(browser, testInfo, USERS.analystOrgA, async (page) => {
    const toolbar = new DraftToolbarPageModel(page);

    await test.step('Step 5: AnalystOrgA moves the draft to "Mo manager review"', async () => {
      await openDraftPage(page, draftId);
      await toolbar.openTransition('Request MO manager review');
      await toolbar.assertStatus('MO MANAGER REVIEW');
    });

    await test.step('Step 6: AnalystOrgA is now view-only at "Mo manager review"', async () => {
      await openDraftPage(page, draftId);
      await toolbar.assertNoTransitions();
    });
  });

  await asPersona(browser, testInfo, USERS.managerOrgA, async (page) => {
    const toolbar = new DraftToolbarPageModel(page);
    const overview = new DraftOverviewPageModel(page);

    await test.step('Step 7: ManagerOrgA can edit and sees REJECT + "Send to OrgC for review"', async () => {
      // The "Update" button lives on the draft's Overview tab, not Containers.
      await openDraftPage(page, draftId, 'overview');
      await overview.assertCanEdit();
      await toolbar.assertTransitionVisible('Reject');
      await toolbar.assertTransitionVisible('Send to OrgC for review');
    });

    await test.step('Step 8: ManagerOrgA moves the draft to "OrgC analyst review"', async () => {
      await toolbar.openTransition('Send to OrgC for review');
      await toolbar.assertStatus('ORGC ANALYST REVIEW');
    });

    await test.step('Step 9: ManagerOrgA is now view-only at "OrgC analyst review"', async () => {
      await openDraftPage(page, draftId);
      await toolbar.assertNoTransitions();
    });
  });
});

test('Threat Advisory happy flow - phase 3: OrgC review (steps 10-13)', { tag: ['@ee', '@workflow'] }, async ({ browser, playwright, baseURL }, testInfo) => {
  test.setTimeout(300000);
  // Starting state: the draft as steps 5 and 8 leave it, at "OrgC analyst review".
  const draftId = await submitThreatAdvisoryDraftViaApi(playwright, baseURL!, newReportName());
  await advanceDraftViaApi(playwright, baseURL!, draftId, 'ORGC ANALYST REVIEW');

  await asPersona(browser, testInfo, USERS.analystOrgC, async (page) => {
    const toolbar = new DraftToolbarPageModel(page);

    await test.step('Step 10: AnalystOrgC sees "SEND TO ORGC MANAGER" + REJECT', async () => {
      await openDraftPage(page, draftId);
      await toolbar.assertTransitionVisible('SEND TO ORGC MANAGER');
      await toolbar.assertTransitionVisible('Reject');
    });

    await test.step('Step 11: AnalystOrgC moves the draft to "OrgC manager review"', async () => {
      await toolbar.openTransition('SEND TO ORGC MANAGER');
      await toolbar.assertStatus('ORGC MANAGER REVIEW');
    });

    await test.step('Step 12: AnalystOrgC is now view-only at "OrgC manager review"', async () => {
      await openDraftPage(page, draftId);
      await toolbar.assertNoTransitions();
    });
  });

  await test.step('Step 13: ManagerOrgC sees "SHARE TO ORG" + REJECT', async () => {
    await asPersona(browser, testInfo, USERS.managerOrgC, async (page) => {
      const toolbar = new DraftToolbarPageModel(page);
      await openDraftPage(page, draftId);
      await toolbar.assertTransitionVisible('SHARE TO ORG');
      await toolbar.assertTransitionVisible('Reject');
    });
  });
});

test('Threat Advisory happy flow - phase 4: sharing, validation and Report access (steps 14-17, 19-24)', { tag: ['@ee', '@workflow'] }, async ({ browser, playwright, baseURL }, testInfo) => {
  test.setTimeout(420000);
  const reportName = newReportName();
  // Starting state: the draft as steps 5, 8 and 11 leave it, at "OrgC manager review".
  const draftId = await submitThreatAdvisoryDraftViaApi(playwright, baseURL!, reportName);
  await advanceDraftViaApi(playwright, baseURL!, draftId, 'ORGC MANAGER REVIEW');

  await asPersona(browser, testInfo, USERS.managerOrgC, async (page) => {
    const toolbar = new DraftToolbarPageModel(page);

    await test.step('Steps 14-15: ManagerOrgC shares to OrgB, task succeeds, status becomes "Ready for validation"', async () => {
      await openDraftPage(page, draftId);
      await toolbar.openTransition('SHARE TO ORG');
      await toolbar.fillWizard({ share: ['OrgB'] });
      await expect(toolbar.getToolbar().getByText('READY FOR VALIDATION', { exact: true })).toBeVisible({ timeout: 30000 });
    });

    await test.step('Step 16: AnalystOrgB still cannot see the draft (entities shared, draft itself is not)', async () => {
      await asPersona(browser, testInfo, USERS.analystOrgB, async (orgBPage) => {
        await openDraftPage(orgBPage, draftId);
        await new DraftToolbarPageModel(orgBPage).assertNoAccess();
      });
    });

    await test.step('Step 17: ManagerOrgC validates the draft, exits draft mode, Report is created', async () => {
      await gotoDraft(page, draftId);
      await toolbar.openTransition('Validate');
      await toolbar.fillWizard();
      await page.waitForURL('**/dashboard/data/import/draft');
    });
  });

  // Step 18: the "Report created" playbook sets the final authorized members.
  await waitForReportAccessApplied(playwright, baseURL!, reportName);

  const checkReport = async (
    persona: typeof USERS[keyof typeof USERS],
    checks: (reportDetails: ReportDetailsPage) => Promise<void>,
  ) => asPersona(browser, testInfo, persona, async (page) => {
    const reportPage = new ReportPage(page);
    await reportPage.navigateFromMenu();
    await reportPage.getItemFromList(reportName).click();
    await checks(new ReportDetailsPage(page));
  });

  await test.step('Step 19: AnalystOrgB can view the Report, author is restricted, cannot edit', async () => {
    await checkReport(USERS.analystOrgB, async (reportDetails) => {
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthorRestricted();
    });
  });

  await test.step('Step 20: ManagerOrgB can view the Report, author is restricted, cannot edit', async () => {
    await checkReport(USERS.managerOrgB, async (reportDetails) => {
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthorRestricted();
    });
  });

  await test.step('Step 21: AnalystOrgA can view the Report, author = OrgA, cannot edit', async () => {
    await checkReport(USERS.analystOrgA, async (reportDetails) => {
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthor('OrgA');
    });
  });

  await test.step('Step 22: ManagerOrgA can view the Report, author = OrgA, cannot edit', async () => {
    await checkReport(USERS.managerOrgA, async (reportDetails) => {
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthor('OrgA');
    });
  });

  await test.step('Step 23: AnalystOrgC can view the Report, author = OrgA, cannot edit', async () => {
    await checkReport(USERS.analystOrgC, async (reportDetails) => {
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthor('OrgA');
    });
  });

  // "can manage" (admin access_right) inherently includes edit rights.
  await test.step('Step 24: ManagerOrgC can view and edit the Report, and can manage authorized members', async () => {
    await checkReport(USERS.managerOrgC, async (reportDetails) => {
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: true, canManageAuthorizedMembers: true });
      await reportDetails.assertAuthor('OrgA');
    });
  });
});

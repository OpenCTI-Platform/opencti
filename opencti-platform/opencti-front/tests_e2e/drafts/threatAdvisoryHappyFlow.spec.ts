/**
 * Content of the test
 * --------------------
 * Implements the authoritative "happy flow" scenario (24 steps) from
 * `workflow-e2e-product-test-plan.md` (repo memory): a Threat Advisory Report is submitted via
 * the Form Intake as a draft, moved through every Threat Advisory workflow status by the correct
 * persona at each step (with view-only/no-access checks in between), shared to OrgB, validated
 * into a real Report, then its final authorized members (set by the "Report created" playbook)
 * are checked from every persona's point of view.
 *
 * Depends on the fixtures built by `workflow/threatAdvisoryWorkflowSetup.spec.ts` and
 * `formIntake/threatAdvisorySetup.spec.ts` (workflow + "Threat Advisories" form + playbook),
 * and the 6-user/3-org/4-group test-data matrix seeded by the `'init data'` project.
 *
 * NOTE on workflow status display names: the draft toolbar (`ItemStatus.tsx`) renders the status
 * *template* name verbatim (raw, e.g. "NEW"/"MO MANAGER REVIEW"/...) - `snakeCaseToSentenceCase`
 * is only applied in the Workflow Editor's graph nodes (`StatusNode.tsx`), not at runtime.
 *
 * NOTE on submitting the form: analysts use the "Import data" icon button in the top bar
 * (`UploadImport.tsx`), not the Integrations/Deployed catalog (which is for admins deploying
 * forms, not for submitting them) - see `ImportFilesDialogPageModel`.
 */
import { expect, test } from '../fixtures/baseFixtures';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import ImportFilesDialogPageModel from '../model/formIntake/importFilesDialog.pageModel';
import FormIntakeFillPageModel from '../model/formIntake/formIntakeFill.pageModel';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import DraftOverviewPageModel from '../model/drafts/draftOverview.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import { restoreAdminSession } from '../restoreAdminSession';

const findLatestReportName = async (request: import('@playwright/test').APIRequestContext, namePrefix: string): Promise<string> => {
  const query = `
    query {
      reports(first: 1, orderBy: created_at, orderMode: desc, search: "${namePrefix}") {
        edges {
          node {
            name
          }
        }
      }
    }
  `;
  const response = await request.post('/graphql', { data: { query } });
  const responseData = JSON.parse((await response.body()).toString());
  if (responseData.errors) {
    throw new Error(`findLatestReportName failed: ${JSON.stringify(responseData.errors)}`);
  }
  const name = responseData.data?.reports?.edges?.[0]?.node?.name;
  if (!name) {
    throw new Error(`No Report found with a name starting with "${namePrefix}" - run "Steps 1-18" at least once first.`);
  }
  return name;
};

const USERS = {
  analystOrgA: { email: 'analystorga@filigran.test', password: 'analystorga' },
  managerOrgA: { email: 'managerorga@filigran.test', password: 'managerorga' },
  analystOrgB: { email: 'analystorgb@filigran.test', password: 'analystorgb' },
  managerOrgB: { email: 'managerorgb@filigran.test', password: 'managerorgb' },
  analystOrgC: { email: 'analystorgc@filigran.test', password: 'analystorgc' },
  managerOrgC: { email: 'managerorgc@filigran.test', password: 'managerorgc' },
};

// Avoid a raw numeric/date-like suffix: some views reformat name substrings that look like
// timestamps into a human-readable date, which breaks exact-text matching later.
// Set E2E_REPORT_NAME to re-run only the "Report access checks" test against a Report already
// created by a previous full run, instead of waiting through steps 1-18 again:
//   E2E_REPORT_NAME="Threat Advisory E2E - <uuid>" npx playwright test threatAdvisoryHappyFlow.spec.ts -g "Report access checks"
// If omitted when run standalone, the most recently created "Threat Advisory E2E - ..." Report is used instead.
const REPORT_NAME_PREFIX = 'Threat Advisory E2E - ';
let reportName: string = process.env.E2E_REPORT_NAME ?? `${REPORT_NAME_PREFIX}${crypto.randomUUID()}`;
let draftId = '';

test.describe.serial('Threat Advisory happy flow', () => {
  test('Steps 1-18: submission through workflow to Report validation', { tag: ['@ee', '@group1'] }, async ({ page }) => {
    test.skip(!!process.env.E2E_REPORT_NAME, 'E2E_REPORT_NAME set - reusing an existing Report, skipping creation');
    test.setTimeout(600000); // ~10 logins/transitions across the full scenario

    const topBar = new TopMenuProfilePage(page);
    const loginForm = new LoginFormPageModel(page);
    const importDialog = new ImportFilesDialogPageModel(page);
    const formFill = new FormIntakeFillPageModel(page, importDialog.getRoot());
    const toolbar = new DraftToolbarPageModel(page);
    const overview = new DraftOverviewPageModel(page);

    const loginAs = async (user: { email: string; password: string }) => {
      await topBar.logout();
      await loginForm.login(user.email, user.password);
      // A previous, interrupted test run may have left this user stuck in a draft context.
      await toolbar.exitDraftIfPresent();
    };

    const openDraft = async (user: { email: string; password: string }) => {
      await loginAs(user);
      // Report is a Container-type entity, shown under the "Containers" tab, not "Entities"
      // (the default tab excludes containers).
      await page.goto(`/dashboard/data/import/draft/${draftId}/containers`, { waitUntil: 'domcontentloaded' });
    };

    await test.step('Step 1: AnalystOrgA submits the Threat Advisory form as a draft (status New)', async () => {
      await page.goto('/');
      await loginAs(USERS.analystOrgA);
      await importDialog.open();
      await importDialog.selectFormMode();
      await importDialog.selectForm('Threat Advisories');
      await formFill.assertLoaded();
      await formFill.fillTextField('Name', reportName);
      await formFill.selectAuthor('OrgA');
      await formFill.submit();
      draftId = await formFill.waitForDraftCreated();
      await toolbar.assertStatus('NEW');
    });

    await test.step('Step 2: AnalystOrgC cannot see the draft', async () => {
      await openDraft(USERS.analystOrgC);
      await toolbar.assertNoAccess();
    });

    await test.step('Step 3: ManagerOrgB cannot see the draft', async () => {
      await openDraft(USERS.managerOrgB);
      await toolbar.assertNoAccess();
    });

    await test.step('Step 4: ManagerOrgA can view but cannot transition (view-only)', async () => {
      await openDraft(USERS.managerOrgA);
      await overview.assertName(reportName);
      await toolbar.assertNoTransitions();
    });

    await test.step('Step 5: AnalystOrgA moves the draft to "Mo manager review"', async () => {
      await openDraft(USERS.analystOrgA);
      await toolbar.openTransition('Request MO manager review');
      await toolbar.assertStatus('MO MANAGER REVIEW');
    });

    await test.step('Step 6: AnalystOrgA is now view-only at "Mo manager review"', async () => {
      await openDraft(USERS.analystOrgA);
      await toolbar.assertNoTransitions();
    });

    await test.step('Step 7: ManagerOrgA can edit and sees REJECT + "Send to OrgC for review"', async () => {
      await openDraft(USERS.managerOrgA);
      // The "Update" button lives on the draft's Overview tab, not Containers.
      await page.goto(`/dashboard/data/import/draft/${draftId}/overview`, { waitUntil: 'domcontentloaded' });
      await overview.assertCanEdit();
      await expect(toolbar.getTransitionsActions().getByText('Reject')).toBeVisible();
      await expect(toolbar.getTransitionsActions().getByText('Send to OrgC for review')).toBeVisible();
    });

    await test.step('Step 8: ManagerOrgA moves the draft to "OrgC analyst review"', async () => {
      await toolbar.openTransition('Send to OrgC for review');
      await toolbar.assertStatus('ORGC ANALYST REVIEW');
    });

    await test.step('Step 9: ManagerOrgA is now view-only at "OrgC analyst review"', async () => {
      await openDraft(USERS.managerOrgA);
      await toolbar.assertNoTransitions();
    });

    await test.step('Step 10: AnalystOrgC sees "SEND TO ORGC MANAGER" + REJECT', async () => {
      await openDraft(USERS.analystOrgC);
      await expect(toolbar.getTransitionsActions().getByText('SEND TO ORGC MANAGER')).toBeVisible();
      await expect(toolbar.getTransitionsActions().getByText('Reject')).toBeVisible();
    });

    await test.step('Step 11: AnalystOrgC moves the draft to "OrgC manager review"', async () => {
      await toolbar.openTransition('SEND TO ORGC MANAGER');
      await toolbar.assertStatus('ORGC MANAGER REVIEW');
    });

    await test.step('Step 12: AnalystOrgC is now view-only at "OrgC manager review"', async () => {
      await openDraft(USERS.analystOrgC);
      await toolbar.assertNoTransitions();
    });

    await test.step('Step 13: ManagerOrgC sees "SHARE TO ORG" + REJECT', async () => {
      await openDraft(USERS.managerOrgC);
      await expect(toolbar.getTransitionsActions().getByText('SHARE TO ORG')).toBeVisible();
      await expect(toolbar.getTransitionsActions().getByText('Reject')).toBeVisible();
    });

    await test.step('Steps 14-15: ManagerOrgC shares to OrgB, task succeeds, status becomes "Ready for validation"', async () => {
      await toolbar.openTransition('SHARE TO ORG');
      await toolbar.fillOrgPickerStep({ share: ['OrgB'] });
      await expect(toolbar.getToolbar().getByText('READY FOR VALIDATION', { exact: true })).toBeVisible({ timeout: 30000 });
    });

    await test.step('Step 16: AnalystOrgB still cannot see the draft (entities shared, draft itself is not)', async () => {
      await openDraft(USERS.analystOrgB);
      await toolbar.assertNoAccess();
    });

    await test.step('Step 17: ManagerOrgC validates the draft, exits draft mode, Report is created', async () => {
      await openDraft(USERS.managerOrgC);
      await toolbar.openTransition('Validate');
      await toolbar.confirmValidateDraft();
      await page.waitForURL('**/dashboard/data/import/draft');
    });

    // Step 18 (backend/playbook): the "Report created" playbook applies the final Report-level
    // authorized members (OrgC+OrgC Manager group=manage, Analyst/Manager/OrgC Analyst groups=view) -
    // no direct UI action, verified indirectly in "Report access checks" below.

    await restoreAdminSession(page);
  });

  test('Report access checks (steps 19-24): every persona\'s view of the validated Report', { tag: ['@ee', '@group1'] }, async ({ page, request }) => {
    test.setTimeout(180000); // ~6 logins across every persona

    // Standalone run (e.g. from the UI test runner): "Steps 1-18" didn't run in this session,
    // so find the most recently created matching Report instead of using a fresh random name.
    if (!draftId && !process.env.E2E_REPORT_NAME) {
      reportName = await findLatestReportName(request, REPORT_NAME_PREFIX);
    }

    const topBar = new TopMenuProfilePage(page);
    const loginForm = new LoginFormPageModel(page);
    const toolbar = new DraftToolbarPageModel(page);
    const reportPage = new ReportPage(page);
    const reportDetails = new ReportDetailsPage(page);

    const loginAs = async (user: { email: string; password: string }) => {
      await topBar.logout();
      await loginForm.login(user.email, user.password);
      // A previous, interrupted test run may have left this user stuck in a draft context.
      await toolbar.exitDraftIfPresent();
    };

    await page.goto('/');

    await test.step('Step 19: AnalystOrgB can view the Report, author is restricted, cannot edit', async () => {
      await loginAs(USERS.analystOrgB);
      await reportPage.navigateFromMenu();
      await reportPage.getItemFromList(reportName).click();
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthorRestricted();
    });

    await test.step('Step 20: ManagerOrgB can view the Report, author is restricted, cannot edit', async () => {
      await loginAs(USERS.managerOrgB);
      await reportPage.navigateFromMenu();
      await reportPage.getItemFromList(reportName).click();
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthorRestricted();
    });

    await test.step('Step 21: AnalystOrgA can view the Report, author = OrgA, cannot edit', async () => {
      await loginAs(USERS.analystOrgA);
      await reportPage.navigateFromMenu();
      await reportPage.getItemFromList(reportName).click();
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthor('OrgA');
    });

    await test.step('Step 22: ManagerOrgA can view the Report, author = OrgA, cannot edit', async () => {
      await loginAs(USERS.managerOrgA);
      await reportPage.navigateFromMenu();
      await reportPage.getItemFromList(reportName).click();
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthor('OrgA');
    });

    await test.step('Step 23: AnalystOrgC can view the Report, author = OrgA, cannot edit', async () => {
      await loginAs(USERS.analystOrgC);
      await reportPage.navigateFromMenu();
      await reportPage.getItemFromList(reportName).click();
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: false });
      await reportDetails.assertAuthor('OrgA');
    });

    // "can manage" (admin access_right) inherently includes edit rights - there's no
    // manage-only tier in the access-control model, unlike the product test plan's wording implies.
    await test.step('Step 24: ManagerOrgC can view and edit the Report, and can manage authorized members', async () => {
      await loginAs(USERS.managerOrgC);
      await reportPage.navigateFromMenu();
      await reportPage.getItemFromList(reportName).click();
      await reportDetails.assertReportAccess({ name: reportName, canView: true, canEdit: true, canManageAuthorizedMembers: true });
      await reportDetails.assertAuthor('OrgA');
    });

    await restoreAdminSession(page);
  });
});

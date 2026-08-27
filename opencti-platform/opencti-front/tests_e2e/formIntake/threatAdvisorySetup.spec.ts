/**
 * Content of the test
 * --------------------
 * Create, as ManagerOrgC, the "Threat Advisories" Form Intake definition used by every downstream
 * Threat Advisory scenario spec to submit a new draft: main entity = Report, created as a draft by
 * default (author reused from the main entity), matching the authoritative product test plan's
 * step 1 ("AnalystOrgA creates a Report via Form Intake... created in a Draft with status NEW").
 *
 * See `workflow-e2e-progress.md` (repo memory) for the scope simplification made here: additional
 * entities/relationships and the form's own optional draft-authorized-members override are left
 * untouched, since draft access control is already fully covered by the Threat Advisory workflow's
 * NEW-status authorized-members rule (built in `threatAdvisoryWorkflowSetup.spec.ts`).
 */
import { expect, test } from '../fixtures/baseFixtures';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import IntegrationsPage from '../model/integrations.pageModel';
import FormIntakeCatalogPageModel from '../model/formIntake/formIntakeCatalog.pageModel';
import FormIntakeBuilderPageModel from '../model/formIntake/formIntakeBuilder.pageModel';
import PlaybookBuilderPageModel from '../model/playbook/playbookBuilder.pageModel';
import { restoreAdminSession } from '../restoreAdminSession';

test('Create the "Threat Advisories" form intake definition', { tag: ['@ee', '@group1'] }, async ({ page }) => {
  test.setTimeout(300000); // 5 minutes, to allow for slow dev-mode SPA reloads
  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);
  const integrations = new IntegrationsPage(page);
  const catalog = new FormIntakeCatalogPageModel(page);
  const builder = new FormIntakeBuilderPageModel(page);

  await page.goto('/');
  await topBar.logout();
  await loginForm.login('managerorgc@filigran.test', 'managerorgc');

  await test.step('Delete any pre-existing "Threat Advisories" form intake', async () => {
    await catalog.goToDeployed();
    await integrations.deleteDeployedIfExists('Threat Advisories');
  });

  await test.step('Open the "Create a form intake" drawer', async () => {
    await catalog.goToAvailable();
    await catalog.clickCreateFormIntake();
    await expect(builder.getDraftByDefaultToggle()).toBeVisible();
  });

  await test.step('Configure the "Threat Advisories" form (main entity = Report, draft by default, author reused)', async () => {
    await builder.setName('Threat Advisories');
    await builder.setDescription('Structured intake form used by analysts to submit Threat Advisory reports for review and validation.');
    // Main entity type defaults to "Report" already - no need to change it.
    // Add a "Created By" field on the Report itself, so the submitting analyst can pick the
    // Report's actual author (per the product test plan's step 1: "author of Report = OrgA") -
    // "Main entity author (reuse the same author)" below only reuses THIS value for the draft's
    // own authorized-members computation, it doesn't set the Report's author on its own.
    await builder.addMainEntityField();
    await builder.setLastMainEntityFieldAttribute('Created By');
    await builder.toggleDraftByDefault();
    await builder.openAdvancedDraftSettings();
    await builder.setDraftAuthorSource('Main entity author (reuse the same author)');
  });

  await test.step('Configure the draft\'s initial authorized members (NEW-status rule: OrgA view, OrgA+Analyst edit)', async () => {
    // formSubmit does not fire the Workflow's NEW-status onEnter action (unlike manually-created
    // drafts), so this override IS the source of truth for a freshly-submitted draft's access.
    await builder.toggleAccessRestriction();
    const authorizedMembers = builder.getAuthorizedMembersField();
    await authorizedMembers.removeDefaultCreatorsMember();
    await authorizedMembers.addMember('OrgA', 'can view');
    await authorizedMembers.addMember('OrgA', 'can edit', ['Analyst group']);
    await builder.clickCreate();
  });

  await test.step('Verify the form intake was created', async () => {
    await expect(catalog.getFormIntakeCard()).toBeVisible();
    await catalog.goToDeployed();
    // Filter by name: the deployed list isn't scoped to form intakes and could paginate the new one out of view.
    await integrations.search('Threat Advisories');
    await expect(integrations.getDeployedRow('Threat Advisories')).toBeVisible();
  });

  await restoreAdminSession(page);
});

test('Create and activate the Threat Advisory Report access-restrictions playbook', { tag: ['@ee', '@group1'] }, async ({ page }) => {
  test.setTimeout(300000); // 5 minutes, to allow for slow dev-mode SPA reloads
  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);
  const playbook = new PlaybookBuilderPageModel(page);

  await page.goto('/');
  await topBar.logout();
  await loginForm.login('managerorgc@filigran.test', 'managerorgc');

  await test.step('Create the playbook', async () => {
    await playbook.goto();
    await playbook.createPlaybook(
      'Threat Advisory Report access restrictions',
      'On every Report creation, applies the final authorized members for the Threat Advisory scenario.',
    );
  });

  await test.step('Add the "Listen knowledge events" trigger, filtered to Report creation', async () => {
    await playbook.clickPlaceholder();
    await playbook.selectComponent('Listen knowledge events');
    await playbook.setComponentName('Report created');
    await playbook.addFilter('Entity type', 'Report');
    await playbook.submitComponent();
  });

  await test.step('Add the "Manage access restrictions" action with the final authorized-members rules', async () => {
    await playbook.clickPlaceholder();
    await playbook.selectComponent('Manage access restrictions');
    await playbook.setComponentName('Apply Threat Advisory Report access');

    // Default "Everyone on the platform" row is already "no access" - nothing to remove here.
    const accessRestrictions = playbook.getAccessRestrictionsField();
    await accessRestrictions.addMember('OrgC', 'can manage', ['OrgC Manager group']);
    await accessRestrictions.addMember('Analyst group', 'can view');
    await accessRestrictions.addMember('Manager group', 'can view');
    await accessRestrictions.addMember('OrgC Analyst group', 'can view');

    await playbook.submitComponent();
  });

  await test.step('Add the terminal "Send for ingestion" node - without it the access-restriction patch is only computed in-memory and never persisted', async () => {
    await playbook.clickPlaceholder();
    await playbook.selectComponent('Send for ingestion');
    await playbook.setComponentName('Persist access restrictions');
    await playbook.submitComponent();
  });

  await test.step('Activate the playbook', async () => {
    await playbook.startPlaybook();
    await expect(page.getByText('Playbook is running')).toBeVisible();
  });

  // See threatAdvisoryWorkflowSetup.spec.ts: logout() destroys the shared admin session
  // server-side, so restore it for downstream 'chromium'-project specs.
  await restoreAdminSession(page);
});

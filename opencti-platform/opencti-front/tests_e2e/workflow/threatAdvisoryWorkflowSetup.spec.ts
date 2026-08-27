import { expect, test } from '../fixtures/baseFixtures';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import WorkflowEditorPageModel from '../model/workflow/workflowEditor.pageModel';
import WorkflowEditionDrawerPageModel from '../model/workflow/workflowEditionDrawer.pageModel';
import DraftToolbarPageModel from '../model/drafts/draftToolbar.pageModel';
import { restoreAdminSession } from '../restoreAdminSession';

test('Build and publish the Threat Advisory draft workflow', { tag: ['@ee', '@group1'] }, async ({ page }) => {
  test.setTimeout(300000);

  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);
  const workflowEditor = new WorkflowEditorPageModel(page);
  const drawer = new WorkflowEditionDrawerPageModel(page);
  const toolbar = new DraftToolbarPageModel(page);

  await page.goto('/');
  await topBar.logout();
  await loginForm.login('managerorgc@filigran.test', 'managerorgc');
  // A previous, interrupted test run may have left this user stuck in a draft context.
  await toolbar.exitDraftIfPresent();

  await workflowEditor.goto();

  await test.step('Clear any pre-existing workflow definition', async () => {
    await workflowEditor.clearWorkflow();
  });

  await test.step('Add status NEW', async () => {
    await workflowEditor.clickAddStatus();
    await drawer.selectOrCreateStatusTemplate('NEW', '#4caf50');
    await drawer.getOnEnterAuthorizedMembersToggle().click();
    const onEnter = drawer.getOnEnterAuthorizedMembers();
    await onEnter.removeDefaultCreatorsMember();
    await onEnter.addMember('OrgA', 'can view');
    await onEnter.addMember('OrgA', 'can edit', ['Analyst group']);
    await drawer.clickSubmit();
    await expect(workflowEditor.getNodeByLabel('New')).toBeVisible();
  });

  await test.step('Add status MO MANAGER REVIEW + transition "Request MO manager review"', async () => {
    await workflowEditor.clickPlaceholder();
    await drawer.selectOrCreateStatusTemplate('MO MANAGER REVIEW', '#ff9800');
    await drawer.getOnEnterAuthorizedMembersToggle().click();
    const onEnter = drawer.getOnEnterAuthorizedMembers();
    await onEnter.removeDefaultCreatorsMember();
    await onEnter.addMember('OrgA', 'can view');
    await onEnter.addMember('OrgA', 'can edit', ['Manager group']);
    await drawer.clickSubmit();
    await expect(workflowEditor.getNodeByLabel('Mo manager review')).toBeVisible();

    await workflowEditor.clickNewTransitionNode();
    await drawer.setTransitionName('Request MO manager review');
    // Restrict to OrgA analysts only, otherwise any user with edit access at this status sees it.
    await drawer.getConditionFilters().addFilter('Is in organization', 'OrgA');
    await drawer.getConditionFilters().addFilter('Is in group', 'Analyst group');
    await drawer.clickSubmit();
  });

  await test.step('Add status ORGC ANALYST REVIEW + transition "Send to OrgC for review"', async () => {
    await workflowEditor.clickPlaceholder();
    await drawer.selectOrCreateStatusTemplate('ORGC ANALYST REVIEW', '#ff9800');
    await drawer.getOnEnterAuthorizedMembersToggle().click();
    const onEnter = drawer.getOnEnterAuthorizedMembers();
    await onEnter.removeDefaultCreatorsMember();
    await onEnter.addMember('OrgA', 'can view');
    await onEnter.addMember('OrgC', 'can view');
    await onEnter.addMember('OrgC', 'can edit', ['OrgC Analyst group']);
    await drawer.clickSubmit();
    await expect(workflowEditor.getNodeByLabel('OrgC analyst review')).toBeVisible();

    await workflowEditor.clickNewTransitionNode();
    await drawer.setTransitionName('Send to OrgC for review');
    await drawer.getConditionFilters().addFilter('Is in organization', 'OrgA');
    await drawer.getConditionFilters().addFilter('Is in group', 'Manager group');
    await drawer.clickSubmit();
  });

  await test.step('Add status ORGC MANAGER REVIEW + transition "SEND TO ORGC MANAGER"', async () => {
    await workflowEditor.clickPlaceholder();
    await drawer.selectOrCreateStatusTemplate('ORGC MANAGER REVIEW', '#f44336');
    await drawer.getOnEnterAuthorizedMembersToggle().click();
    const onEnter = drawer.getOnEnterAuthorizedMembers();
    await onEnter.removeDefaultCreatorsMember();
    await onEnter.addMember('OrgA', 'can view');
    await onEnter.addMember('OrgC', 'can view');
    await onEnter.addMember('OrgC', 'can edit', ['OrgC Manager group']);
    await drawer.clickSubmit();
    await expect(workflowEditor.getNodeByLabel('OrgC manager review')).toBeVisible();

    await workflowEditor.clickNewTransitionNode();
    await drawer.setTransitionName('SEND TO ORGC MANAGER');
    await drawer.getConditionFilters().addFilter('Is in organization', 'OrgC');
    await drawer.getConditionFilters().addFilter('Is in group', 'OrgC Analyst group');
    await drawer.clickSubmit();
  });

  await test.step('Add status READY for Validation + transition "SHARE TO ORG"', async () => {
    await workflowEditor.clickPlaceholder();
    await drawer.selectOrCreateStatusTemplate('READY FOR VALIDATION', '#2196f3');
    await drawer.clickSubmit();
    await expect(workflowEditor.getNodeByLabel('Ready for validation')).toBeVisible();

    await workflowEditor.clickNewTransitionNode();
    await drawer.setTransitionName('SHARE TO ORG');
    await drawer.getConditionFilters().addFilter('Is in organization', 'OrgC');
    await drawer.getConditionFilters().addFilter('Is in group', 'OrgC Manager group');
    // Org picked at trigger time (org-picker popup), so leave "Organizations" empty here.
    await drawer.getShareWithOrganizationsToggle().click();
    await drawer.clickSubmit();
  });

  await test.step('Add terminal transition "Validate" (no target status)', async () => {
    await workflowEditor.clickPlaceholder();
    await drawer.selectOrCreateStatusTemplate('ZZZ_THROWAWAY_DELETE_ME', '#9e9e9e');
    await drawer.clickSubmit();

    await workflowEditor.clickNewTransitionNode();
    await drawer.setTransitionName('Validate');
    await drawer.getConditionFilters().addFilter('Is in organization', 'OrgC');
    await drawer.getConditionFilters().addFilter('Is in group', 'OrgC Manager group');
    await drawer.getValidateDraftToggle().click();
    await drawer.clickSubmit();

    await workflowEditor.clickNodeByLabel('Zzz throwaway delete me');
    await drawer.clickDelete();
    await expect(workflowEditor.getNodeByLabel('Zzz throwaway delete me')).toBeHidden();
  });

  await test.step('Reload to snapshot the persisted initialState before adding back-edges', async () => {
    // TODO(Octave): check why reload required here
    await workflowEditor.reload();
    await expect(workflowEditor.getNodeByLabel('New')).toBeVisible();
  });

  // Each "Reject" transition is only triggerable by whoever can edit at that source status.
  const rejectSources: { label: string; org: string; group: string }[] = [
    { label: 'Mo manager review', org: 'OrgA', group: 'Manager group' },
    { label: 'OrgC analyst review', org: 'OrgC', group: 'OrgC Analyst group' },
    { label: 'OrgC manager review', org: 'OrgC', group: 'OrgC Manager group' },
  ];
  for (const { label, org, group } of rejectSources) {
    await test.step(`Add "Reject" transition from ${label} to New`, async () => {
      await workflowEditor.dragConnectStatuses(label, 'New');
      await workflowEditor.clickNewTransitionNode();
      await drawer.setTransitionName('Reject');
      await drawer.getConditionFilters().addFilter('Is in organization', org);
      await drawer.getConditionFilters().addFilter('Is in group', group);
      await drawer.getEnableCommentToggle().click();
      await drawer.getRequiredCommentToggle().click();
      await drawer.clickSubmit();
    });
  }

  await test.step('Publish the workflow', async () => {
    await workflowEditor.publish();
    await expect(workflowEditor.getPublishButton()).toHaveText('Published');
  });

  // logout() above destroys the shared admin session server-side - restore it for downstream specs.
  await restoreAdminSession(page);
});

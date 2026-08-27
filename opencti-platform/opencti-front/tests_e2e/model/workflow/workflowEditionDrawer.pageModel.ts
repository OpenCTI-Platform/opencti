import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import FiltersPageModel from '../filters.pageModel';
import WorkflowAuthorizedMembersPageModel from './workflowAuthorizedMembers.pageModel';

/**
 * Wraps the `WorkflowEditionDrawer` (StatusForm / TransitionForm), opened by clicking a
 * status/transition/placeholder node or the "Add Status" button in the workflow graph editor
 * (see `workflowEditor.pageModel.ts`). Only one such drawer is ever open at a time, so most
 * fields are looked up directly on `page` - the on-enter/on-exit/authorized-members sections use
 * dedicated container testids since they repeat the same generic field labels.
 */
export default class WorkflowEditionDrawerPageModel {
  private readonly statusTemplateAutocomplete: AutocompleteFieldPageModel;

  constructor(private readonly page: Page) {
    this.statusTemplateAutocomplete = new AutocompleteFieldPageModel(this.page, 'Status', false);
  }

  // --- Status form -----------------------------------------------------

  /**
   * Selects an existing status template by exact name, or creates a new one (with the given
   * color) if none matches. Status templates are a shared/global entity so an earlier test run
   * may already have created it.
   */
  async selectOrCreateStatusTemplate(name: string, color = '#0059f7') {
    const combobox = this.page.getByRole('combobox', { name: 'Status' });
    await combobox.click();
    await combobox.fill(name);
    const option = this.page.getByRole('listbox', { name: 'Status' }).getByText(name, { exact: true });
    let exists = true;
    try {
      await option.waitFor({ state: 'visible', timeout: 3000 });
    } catch {
      exists = false;
    }
    if (exists) {
      return option.click();
    }
    await this.statusTemplateAutocomplete.openAddOptionForm();
    await this.page.getByLabel('Name').fill(name);
    await this.page.getByLabel('Color').fill(color);
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  getOnEnterAuthorizedMembersToggle() {
    return this.page.getByTestId('workflow-status-onenter-authorized-members-toggle');
  }

  getOnExitAuthorizedMembersToggle() {
    return this.page.getByTestId('workflow-status-onexit-authorized-members-toggle');
  }

  getOnEnterAuthorizedMembers() {
    return new WorkflowAuthorizedMembersPageModel(this.page, this.page.getByTestId('workflow-status-onenter-actions-container'));
  }

  getOnExitAuthorizedMembers() {
    return new WorkflowAuthorizedMembersPageModel(this.page, this.page.getByTestId('workflow-status-onexit-actions-container'));
  }

  // --- Transition form ---------------------------------------------------

  getTransitionNameField() {
    return this.page.getByTestId('workflow-transition-name-field');
  }

  setTransitionName(name: string) {
    return this.getTransitionNameField().fill(name);
  }

  /** Wraps the transition's "Conditions" filter block (`WorkflowConditionFilters.tsx`) - gates
   * which users see/can trigger the transition (e.g. `workflow_organization`/`workflow_group`). */
  getConditionFilters() {
    return new FiltersPageModel(this.page);
  }

  getShareWithOrganizationsToggle() {
    return this.page.getByTestId('workflow-transition-share-with-organizations-toggle');
  }

  getUnshareFromOrganizationsToggle() {
    return this.page.getByTestId('workflow-transition-unshare-from-organizations-toggle');
  }

  getUpdateAuthorizedMembersToggle() {
    return this.page.getByTestId('workflow-transition-update-authorized-members-toggle');
  }

  getTransitionAuthorizedMembers() {
    return new WorkflowAuthorizedMembersPageModel(this.page, this.page.getByTestId('workflow-transition-authorized-members-container'));
  }

  getEnableCommentToggle() {
    return this.page.getByTestId('workflow-transition-enable-comment-toggle');
  }

  getRequiredCommentToggle() {
    return this.page.getByTestId('workflow-transition-required-comment-toggle');
  }

  getValidateDraftToggle() {
    return this.page.getByTestId('workflow-transition-validate-draft-toggle');
  }

  // --- Drawer buttons ---------------------------------------------------

  clickSubmit() {
    return this.page.getByTestId('workflow-edition-submit-button').click();
  }

  clickCancel() {
    return this.page.getByTestId('workflow-edition-cancel-button').click();
  }

  clickDelete() {
    return this.page.getByTestId('workflow-edition-delete-button').click();
  }
}

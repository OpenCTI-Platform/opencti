import { Locator, Page } from '@playwright/test';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export type WorkflowAccessRight = 'can view' | 'can use' | 'can edit' | 'can manage';

/**
 * Wraps a single `AuthorizedMembersField` instance (reused by StatusForm's on-enter/on-exit
 * actions and TransitionForm's "Update authorized members" action). Must be scoped to the
 * relevant container (see `workflow-status-onenter-actions-container` /
 * `workflow-status-onexit-actions-container` / `workflow-transition-authorized-members-container`
 * testids) since the member/access-right field labels are generic and repeated across sections.
 */
export default class WorkflowAuthorizedMembersPageModel {
  private readonly memberAutocomplete: AutocompleteFieldPageModel;
  private readonly accessSelect: SelectFieldPageModel;

  constructor(private readonly page: Page, private readonly rootLocator: Locator) {
    this.memberAutocomplete = new AutocompleteFieldPageModel(this.page, 'Users, groups or organizations', false, this.rootLocator);
    this.accessSelect = new SelectFieldPageModel(this.page, 'Access right', false, this.rootLocator);
  }

  /**
   * Adds a new authorized-member row: picks the member, sets its access right, optionally
   * restricts it to a set of groups (only available when the member is an Organization, or a
   * dynamic value that supports it), then confirms with the "Add" button (accessible name "More").
   */
  async addMember(memberName: string, accessRight: WorkflowAccessRight, groupNames: string[] = []) {
    await this.memberAutocomplete.selectOption(memberName);
    await this.accessSelect.selectOption(accessRight);
    if (groupNames.length > 0) {
      await this.rootLocator.getByText('Advanced options').click();
      const groupsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Groups restriction', true, this.rootLocator);
      for (const groupName of groupNames) {
        await groupsAutocomplete.selectOption(groupName);
      }
    }
    return this.rootLocator.getByRole('button', { name: 'More' }).click();
  }

  /** Removes a specific-access row identified by its member's visible label. */
  removeMember(memberName: string) {
    const row = this.rootLocator.getByText(memberName, { exact: true }).locator('../..');
    return row.getByRole('button', { name: 'Delete' }).click();
  }

  /**
   * Toggling "Update authorized members" on always seeds a default "Creators" (dynamic) row
   * with admin access - remove it unless it's explicitly wanted, since the Threat Advisory
   * workflow rules are exhaustive lists of specific org/group grants.
   */
  removeDefaultCreatorsMember() {
    return this.removeMember('Creators');
  }
}

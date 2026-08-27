import { Page } from '@playwright/test';
import FiltersPageModel from '../filters.pageModel';
import TextFieldPageModel from '../field/TextField.pageModel';
import WorkflowAuthorizedMembersPageModel from '../workflow/workflowAuthorizedMembers.pageModel';
import LeftBarPage from '../menu/leftBar.pageModel';

/**
 * Wraps the Automation (playbook) admin UI: `Playbooks.tsx` list page, `PlaybookCreation.tsx`
 * name/description drawer, and the `PlaybookFlow.tsx` react-flow graph editor (`PlaybookFlowAdd
 * Components.tsx` -> `PlaybookFlowSelectComponent.tsx` -> `PlaybookFlowForm.tsx`). Unlike the
 * Workflow graph (Phase 1), playbook nodes/edges are NOT draggable/connectable
 * (`nodesDraggable={false}`/`nodesConnectable={false}` in `PlaybookFlow.tsx`) - the whole graph is
 * built purely by repeatedly clicking the single "+" placeholder node, picking a component from the
 * list, configuring it, and submitting - no drag-connect needed at all.
 */
export default class PlaybookBuilderPageModel {
  constructor(private readonly page: Page) {
  }

  /** Navigates via the left menu (Data > Processing, then the "Automation" tab) instead of a
   * direct URL, to avoid racing a pending full-page reload from a just-completed login. */
  async goto() {
    const leftBar = new LeftBarPage(this.page);
    await leftBar.open();
    await leftBar.clickOnMenu('Data', 'Processing');
    await this.page.getByTestId('create-playbook-button').waitFor({ state: 'visible' });
  }

  /** Opens the "Create a playbook" drawer, fills name/description and submits. */
  async createPlaybook(name: string, description?: string) {
    await this.page.getByTestId('create-playbook-button').click();
    const drawer = this.page.locator('.MuiDrawer-paper');
    await new TextFieldPageModel(this.page, 'Name', 'text', drawer).fill(name);
    if (description) {
      await new TextFieldPageModel(this.page, 'Description', 'text', drawer).fill(description);
    }
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  /** The single "+" placeholder node always present in the graph (`NodePlaceholder.tsx`, `data.name = '+'`). */
  getPlaceholderNode() {
    return this.page.locator('.react-flow__node').filter({ hasText: '+' });
  }

  clickPlaceholder() {
    return this.getPlaceholderNode().click();
  }

  /** Picks a component from the "Add component" list (`PlaybookFlowSelectComponent.tsx`), by its exact visible name. */
  selectComponent(componentName: string) {
    return this.page.getByText(componentName, { exact: true }).click();
  }

  /** The component configuration form's required "Name" field (`PlaybookFlowForm.tsx`). Scoped
   * to the drawer since the playbook's own top-level name is also labeled "Name" on the page. */
  setComponentName(name: string) {
    return new TextFieldPageModel(this.page, 'Name', 'text', this.page.locator('.MuiDrawer-paper')).fill(name);
  }

  /** Adds a filter to the currently-open component's "Filters" field (reuses the generic filters UI). */
  addFilter(filterKey: string, filterLabel: string) {
    return new FiltersPageModel(this.page).addFilter(filterKey, filterLabel);
  }

  /**
   * The "Access restrictions" field of the `PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT` action -
   * same underlying `AuthorizedMembersField` component as the Workflow editor (Phase 1), so the
   * existing generic page model is reused as-is. Only one such field is ever shown per component
   * configuration form, so scoping broadly to the whole page is safe.
   */
  getAccessRestrictionsField() {
    return new WorkflowAuthorizedMembersPageModel(this.page, this.page.locator('body'));
  }

  /** Submits the component configuration form (`PlaybookFlowForm.tsx`, "Create" when adding a new node). */
  submitComponent() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  /** Starts (or stops) the playbook via its popover toggle + confirmation dialog (`PlaybookPopoverToggleDialog.tsx`). */
  async startPlaybook() {
    await this.page.getByTestId('playbook-popover-toggle').click();
    await this.page.getByRole('menuitem', { name: 'Start' }).click();
    return this.page.getByRole('button', { name: 'Confirm' }).click();
  }
}

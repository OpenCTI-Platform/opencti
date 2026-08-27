import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';
import WorkflowAuthorizedMembersPageModel from '../workflow/workflowAuthorizedMembers.pageModel';

export type DraftAuthorSource = 'None (no author specified)' | 'Main entity author (reuse the same author)' | 'Specific Author';

/**
 * Wraps the "Create a form intake" drawer (`FormCreationContainer.tsx` -> `FormCreation.tsx` ->
 * `FormSchemaEditor.tsx`, "Main Entity" tab). Covers the subset of controls needed to define the
 * "Threat Advisories" form: main entity type, draft-by-default, draft author source, and the
 * draft authorized-members override.
 */
export default class FormIntakeBuilderPageModel {
  private readonly drawer: Locator;
  private readonly nameField: TextFieldPageModel;
  private readonly descriptionField: TextFieldPageModel;
  private readonly mainEntityTypeSelect: SelectFieldPageModel;

  constructor(private readonly page: Page) {
    // Scoped to the drawer panel: the "Available" catalog page stays mounted behind it and its
    // "Sort by" select (default value "Name (A-Z)") otherwise makes `getByLabel('Name')` ambiguous.
    this.drawer = page.locator('.MuiDrawer-paper');
    this.nameField = new TextFieldPageModel(page, 'Name', 'text', this.drawer);
    this.descriptionField = new TextFieldPageModel(page, 'Description', 'text', this.drawer);
    this.mainEntityTypeSelect = new SelectFieldPageModel(page, 'Main Entity Type', false, this.drawer);
  }

  setName(name: string) {
    return this.nameField.fill(name);
  }

  setDescription(description: string) {
    return this.descriptionField.fill(description);
  }

  setMainEntityType(entityType: string) {
    return this.mainEntityTypeSelect.selectOption(entityType);
  }

  getDraftByDefaultToggle() {
    return this.page.getByLabel('Create as draft by default');
  }

  toggleDraftByDefault() {
    return this.getDraftByDefaultToggle().click();
  }

  getAllowDraftOverrideToggle() {
    return this.page.getByLabel('Allow users to uncheck draft mode');
  }

  /** Expands the "Advanced Draft Settings" accordion (required before setting the draft author source). */
  openAdvancedDraftSettings() {
    return this.page.getByText('Advanced Draft Settings').click();
  }

  async setDraftAuthorSource(source: DraftAuthorSource) {
    // Its InputLabel isn't aria-linked to the Select (no labelId), so the combobox's accessible
    // name is just the current value - locate it via the adjacent label text instead.
    await this.drawer.getByText('Default author source', { exact: true }).locator('..').getByRole('combobox').click();
    await this.page.getByRole('listbox').getByText(source, { exact: true }).click();
  }

  getAccessRestrictionToggle() {
    return this.page.getByLabel('Activate access restriction');
  }

  /** Enabling always seeds a default "Creators" (admin) row - remove it via `removeDefaultCreatorsMember()` unless explicitly wanted. */
  toggleAccessRestriction() {
    return this.getAccessRestrictionToggle().click();
  }

  getAuthorizedMembersField() {
    return new WorkflowAuthorizedMembersPageModel(this.page, this.drawer);
  }

  /** Adds a new field to the Main Entity Fields section (only one "Add field" button is visible
   * on the "Main Entity" tab outside parsed mode). */
  addMainEntityField() {
    return this.drawer.getByRole('button', { name: 'Add field' }).click();
  }

  /** Sets the "Map to attribute" select for the most-recently-added main-entity field (InputLabel isn't aria-linked, so locate via the adjacent label text). */
  async setLastMainEntityFieldAttribute(attribute: string) {
    await this.drawer.getByText('Map to attribute', { exact: true }).last().locator('..').getByRole('combobox').click();
    await this.page.getByRole('listbox').getByText(attribute, { exact: true }).click();
  }

  clickCreate() {
    // Unscoped, this also matches every built-in card's own "Create" button on the
    // "Available" catalog page still mounted behind the drawer.
    return this.drawer.getByRole('button', { name: 'Create' }).click();
  }

  clickCancel() {
    return this.drawer.getByRole('button', { name: 'Cancel' }).click();
  }
}

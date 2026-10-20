import { Locator, Page, expect } from '@playwright/test';
import TextFieldPageModel from './field/TextField.pageModel';
import SelectFieldPageModel from './field/SelectField.pageModel';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';

/**
 * Selectors come from the real components (src/components/dashboard/variables/*):
 *  - DashboardVariablesBar        -> data-testid `dashboard-variables-bar`, `create-variable-button`
 *  - DashboardVariableChip        -> wrapper data-testid `dashboard-variable-chip-<name>`, a button named
 *                                    `<name> : <value label>` opening a popover with the value input and, for the
 *                                    users who may edit, the buttons `dashboard-variable-edit` / `dashboard-variable-delete`
 *  - DashboardVariableDialog      -> data-testid `dashboard-variable-dialog`, `variable-dialog-submit`
 *  - DashboardVariableDeleteDialog -> data-testid `dashboard-variable-delete-dialog`, `dashboard-variable-delete-confirm`
 */
export default class DashboardVariablesPageModel {
  constructor(private page: Page) {}

  // region Bar and chips

  getBar() {
    return this.page.getByTestId('dashboard-variables-bar');
  }

  getCreateButton() {
    return this.page.getByTestId('create-variable-button');
  }

  getChip(variableName: string) {
    return this.page.getByTestId(`dashboard-variable-chip-${variableName}`);
  }

  /**
   * The clickable chip, named `<name> : <value label>`. The value label is the resolved entity name,
   * or `Not set`.
   */
  getChipButton(variableName: string, valueLabel: string) {
    return this.getChip(variableName).getByRole('button', { name: `${variableName} : ${valueLabel}`, exact: true });
  }

  // endregion

  // region Creation dialog

  getDialog() {
    return this.page.getByTestId('dashboard-variable-dialog');
  }

  getDialogSubmitButton() {
    return this.page.getByTestId('variable-dialog-submit');
  }

  /**
   * Creates an `entity` variable of one entity type, with the only restriction that exists for now
   * (No restriction) and `defaultValueLabel` (the name of an entity of that type) as default value.
   */
  async createEntityVariable(name: string, entityType: string, defaultValueLabel: string) {
    const dialog = this.getDialog();
    await this.getCreateButton().click();
    await expect(dialog).toBeVisible();

    // Every field is there from the start; the ones depending on the type (its parameter, the restriction and
    // the default value) are disabled until it is chosen.
    await new TextFieldPageModel(this.page, 'Name', 'text', dialog).fill(name);
    await new SelectFieldPageModel(this.page, 'Type', false, dialog).selectOption('Entity');
    await new AutocompleteFieldPageModel(this.page, 'Entity types', true, dialog).selectOption(entityType);

    // The restriction only offers `No restriction` (mode none): it must be the checked one.
    await expect(dialog.getByRole('radio', { name: 'No restriction' })).toBeChecked();

    await new AutocompleteFieldPageModel(this.page, 'Default value', false, dialog).selectOption(defaultValueLabel);

    await expect(this.getDialogSubmitButton()).toBeEnabled();
    await this.getDialogSubmitButton().click();
    await expect(dialog).toBeHidden();
  }

  // endregion

  // region Value

  /**
   * Opens the chip popover, searches `valueLabel` in the `Value` field and picks it.
   * The popover is closed afterwards, so the chip and the widgets are reachable again.
   */
  async selectValue(variableName: string, currentValueLabel: string, valueLabel: string) {
    await this.getChipButton(variableName, currentValueLabel).click();
    const valueField = new AutocompleteFieldPageModel(this.page, 'Value', false);
    await valueField.selectOption(valueLabel);
    await this.page.keyboard.press('Escape');
    await expect(this.getChipButton(variableName, valueLabel)).toBeVisible();
  }

  // endregion

  // region Deletion

  getDeleteDialog() {
    return this.page.getByTestId('dashboard-variable-delete-dialog');
  }

  /** Opens the popover of the chip and clicks its Delete variable button (the confirmation dialog opens). */
  async deleteVariable(variableName: string, valueLabel: string): Promise<Locator> {
    await this.getChipButton(variableName, valueLabel).click();
    await this.page.getByTestId('dashboard-variable-delete').click();
    const dialog = this.getDeleteDialog();
    await expect(dialog).toBeVisible();
    return dialog;
  }

  async confirmDeletion() {
    await this.page.getByTestId('dashboard-variable-delete-confirm').click();
    await expect(this.getDeleteDialog()).toBeHidden();
  }

  // endregion
}

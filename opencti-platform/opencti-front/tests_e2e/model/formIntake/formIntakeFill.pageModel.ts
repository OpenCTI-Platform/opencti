import { Locator, Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

/**
 * Wraps a Form Intake submission page (`FormView.tsx`, `/dashboard/integrations/feeds/form/:formId`).
 * `root` scopes all locators - pass the dialog locator when reached via the embedded
 * `ImportFilesDialog` mode, since `getByLabel('Name')` would otherwise also match the underlying
 * Drafts list's "Name" column header.
 */
export default class FormIntakeFillPageModel {
  private readonly root: Locator | Page;

  constructor(private readonly page: Page, root?: Locator) {
    this.root = root ?? page;
  }

  async navigate(formId: string) {
    await this.page.goto(`/dashboard/integrations/feeds/form/${formId}`, { waitUntil: 'domcontentloaded' });
    await this.assertLoaded();
  }

  /** Waits for the dynamic schema-driven form to render (needed when navigating here via a UI click rather than `navigate()`). */
  async assertLoaded() {
    await expect(this.getSubmitButton()).toBeVisible();
  }

  fillTextField(label: string, value: string) {
    // Not exact: MUI appends a literal " *" to the accessible name of required fields.
    return this.root.getByLabel(label).fill(value);
  }

  /** Selects an identity (Organization/Individual/System) in the "Created By" autocomplete field
   * (`CreatedByField.jsx`, rendered for a main-entity field mapped to the "createdBy" attribute). */
  async selectAuthor(name: string) {
    const input = this.root.getByRole('combobox', { name: 'Created By' });
    await input.click();
    await input.fill(name);
    await this.page.getByRole('listbox', { name: 'Created By' }).getByText(name, { exact: true }).click();
  }

  getDraftCheckbox() {
    return this.root.getByRole('checkbox', { name: 'Create as draft' });
  }

  async setSubmitAsDraft(checked: boolean) {
    const checkbox = this.getDraftCheckbox();
    if (await checkbox.isChecked() !== checked) {
      await checkbox.click();
    }
  }

  getAddEntityButton() {
    return this.root.getByRole('button', { name: 'Add' });
  }

  getSubmitButton() {
    return this.root.getByRole('button', { name: 'Submit', exact: true });
  }

  getSubmitError() {
    return this.root.getByRole('alert');
  }

  async submit() {
    await this.getSubmitButton().click();
  }

  /** Waits for the post-submit redirect to the resulting draft, and returns its id. */
  async waitForDraftCreated(): Promise<string> {
    await this.page.waitForURL('**/dashboard/data/import/draft/**');
    const match = this.page.url().match(/\/dashboard\/data\/import\/draft\/([^/?#]+)/);
    if (!match) {
      throw new Error(`Could not extract draft id from URL: ${this.page.url()}`);
    }
    return match[1];
  }
}

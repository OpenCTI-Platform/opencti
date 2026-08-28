import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';

export default class CommitMessagePage {
  private readonly externalReferencesField: AutocompleteFieldPageModel;

  constructor(private page: Page) {
    this.externalReferencesField = new AutocompleteFieldPageModel(page, 'External references', true);
  }

  getPage() {
    return this.page.getByTestId('commit-message-page');
  }

  /**
   * Opens the reference creation form.
   *
   * There is no longer a persistent `Add` button beside the field: MUI's
   * `openCreate` rendered an IconButton labelled "Add", and the library's
   * `onCreateOption` renders a `Create '<text>'` row inside the panel instead.
   * Driving the row is the only way to reach the form — and the row OPENS the
   * form without prefilling it, so callers still fill the source name.
   */
  async openNewReferenceForm(sourceName: string) {
    return this.externalReferencesField.createOption(sourceName);
  }

  getNewReferenceSourceNameInput() {
    return this.page.getByLabel('Source name');
  }

  async fillNewReferenceSourceNameInput(input: string) {
    await this.getNewReferenceSourceNameInput().click();
    return this.getNewReferenceSourceNameInput().fill(input);
  }

  getNewReferenceExternalIDInput() {
    return this.page.getByLabel('External ID');
  }

  async fillNewReferenceExternalIDInput(input: string) {
    await this.getNewReferenceExternalIDInput().click();
    return this.getNewReferenceExternalIDInput().fill(input);
  }

  getNewReferenceCreateButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getValidateButton() {
    return this.page.getByRole('button', { name: 'Validate' });
  }
}

import { Page } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import type { AccessLevelLocator } from './AccessRestriction.pageModel';
import AccessRestrictionPageModel from './AccessRestriction.pageModel';
import DraftAddEntitiesFormPageModel from './form/draftAddEntitiesForm.pageModel';

export default class DraftsPage {
  pageUrl = '/dashboard/data/import/draft';

  private page: Page;
  public accessRestriction: AccessRestrictionPageModel;
  public createEntityPage: DraftAddEntitiesFormPageModel;

  constructor(page: Page) {
    this.page = page;
    this.accessRestriction = new AccessRestrictionPageModel(page);
    this.createEntityPage = new DraftAddEntitiesFormPageModel(page);
  }

  getPage() {
    return this.page.getByTestId('draft-page');
  }

  async navigate() {
    await this.page.goto(this.pageUrl, { waitUntil: 'domcontentloaded' });
    await expect(this.getPage()).toBeVisible();
  }

  getDraft(name: string) {
    return this.page.getByTestId(name).first();
  }

  async deleteDraft(name: string) {
    await this.getDraft(name).getByRole('checkbox').click();
    // await this.page.getByTestId('delete-draftworkspace-button').click();
    // await this.page.getByRole('button', { name: 'Delete' }).click();
  }

  getCreateDraftButton() {
    return this.page.getByTestId('create-draftworkspace-button');
  }

  getCreateDraftDrawer() {
    return this.page.getByTestId('draft-creation-form');
  }

  async createDraft({ name = 'E2E Test Draft', authorizedMembers = [] }: { name?: string; authorizedMembers?: Array<{ name: string; permission: AccessLevelLocator }> }) {
    await this.navigate();
    await this.getCreateDraftButton().click();
    const createDraftDrawer = this.getCreateDraftDrawer();
    await expect(createDraftDrawer).toBeVisible();

    await createDraftDrawer.getByTestId('draft-creation-form-name-input').locator('input').fill(name);

    for (const member of authorizedMembers) {
      await this.accessRestriction.addAccess(member.name, member.permission);
    }
    await this.page.getByRole('button', { name: 'Create' }).click();
  }

  async addEntityToDraft({ type, name }: { type: string; name: string }) {
    await this.page.getByRole('button', { name: 'Create entity' }).click();
    await this.createEntityPage.entityTypeField.selectOption(type);
    await this.createEntityPage.nameField.fill(name);
    return this.createEntityPage.getCreateButton().click();
  }

  getEntityInList(entityName: string) {
    return this.page.getByText(entityName, { exact: true });
  }

  // Click the "remove from draft" icon in the dataTable toolbar
  async clickRemoveFromDraftToolbar() {
    await this.page.getByRole('button', { name: 'Remove from draft' }).click();
  }

  // Confirm removal in the popup by clicking "launch"
  async confirmRemoveEntities() {
    await this.page.getByRole('button', { name: 'Launch' }).click();
  }
}

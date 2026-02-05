import { Page } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import type { AccessLevelLocator } from './AccessRestriction.pageModel';
import AccessRestrictionPageModel from './AccessRestriction.pageModel';

export default class DraftsPage {
  pageUrl = '/dashboard/data/import/draft';

  private page: Page;
  public accessRestriction: AccessRestrictionPageModel;

  constructor(page: Page) {
    this.page = page;
    this.accessRestriction = new AccessRestrictionPageModel(page);
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
    await this.page.getByRole('button', { name: /Add entity/i }).click();
    await this.page.getByLabel(/Entity type/i).selectOption(type);
    await this.page.getByLabel(/Name/i).fill(name);
    await this.page.getByRole('button', { name: /Create/i }).click();
  }

  getEntityInList(entityName: string) {
    return this.page.getByText(entityName, { exact: true });
  }

  // Select the top checkbox to select all entities in the list
  async selectAllEntities() {
    await this.page.getByRole('checkbox', { name: /Select all/i }).check();
  }

  // Click the "remove from draft" icon in the dataTable toolbar
  async clickRemoveFromDraftToolbar() {
    await this.page.getByRole('button', { name: /Remove from draft/i }).click();
  }

  // Confirm removal in the popup by clicking "launch"
  async confirmRemoveEntities() {
    await this.page.getByRole('button', { name: /Launch/i }).click();
  }
}

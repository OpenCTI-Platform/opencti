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

  async createDraft({ name = 'E2E Test Draft', authorizedMembers = [] }: { name?: string; authorizedMembers: Array<{ name: string; permission: AccessLevelLocator }> }) {
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
}

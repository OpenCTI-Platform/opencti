import { Page } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';

export default class RestrictionsPage {
  pageUrl = '/dashboard/data/restriction';

  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('data-management-page');
  }

  async navigateToRestrictedDrafts() {
    await this.page.goto(`${this.pageUrl}/drafts`, { waitUntil: 'domcontentloaded' });
    await expect(this.getPage()).toBeVisible();
  }

  async navigateToRestrictedEntities() {
    await this.page.goto(`${this.pageUrl}/restricted`, { waitUntil: 'domcontentloaded' });
    await expect(this.getPage()).toBeVisible();
  }

  getDraft(name: string) {
    return this.page.getByTestId(name).first();
  }

  async removeRestrictionsOnDraft(name: string) {
    await this.getDraft(name)
      .getByRole('checkbox')
      .click();
    await this.page.getByTestId('remove-auth-members-button').click();
    await this.page.getByRole('button', { name: 'Launch' }).click();
  }
}

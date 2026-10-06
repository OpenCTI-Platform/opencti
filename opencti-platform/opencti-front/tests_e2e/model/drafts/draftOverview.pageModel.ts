import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';
import TextFieldPageModel from '../field/TextField.pageModel';

/**
 * Wraps the draft overview area (`DraftOverview.tsx`): the read-only `DraftDetails`/
 * `DraftBasicInformation` cards, and the "Update" edition drawer (`DraftEdition.tsx`) which is
 * only rendered when the current user has `canEdit` access on the draft.
 */
export default class DraftOverviewPageModel {
  constructor(private readonly page: Page) {
  }

  getUpdateButton() {
    return this.page.getByRole('button', { name: 'Update', exact: true });
  }

  async assertCanEdit() {
    await expect(this.getUpdateButton()).toBeVisible();
  }

  async assertCannotEdit() {
    await expect(this.getUpdateButton()).toHaveCount(0);
  }

  async assertDescription(text: string) {
    await expect(this.page.getByText(text)).toBeVisible();
  }

  async assertName(name: string) {
    await expect(this.page.getByText(name, { exact: true })).toBeVisible();
  }

  getEditionDrawer() {
    return this.page.locator('.MuiDrawer-paper');
  }

  async openEdition() {
    await this.getUpdateButton().click();
    await expect(this.getEditionDrawer()).toBeVisible();
  }

  async editDescription(description: string) {
    await new TextFieldPageModel(this.page, 'Description', 'text', this.getEditionDrawer()).fill(description);
  }

  async closeEdition() {
    await this.page.keyboard.press('Escape');
  }
}

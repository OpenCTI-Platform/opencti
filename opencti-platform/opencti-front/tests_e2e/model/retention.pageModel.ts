import { Locator, Page } from '@playwright/test';

export default class RetentionPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/dashboard/settings/customization/retention');
  }

  getPage() {
    return this.page.getByTestId('retention-page');
  }

  getCreateButton() {
    return this.page.getByTestId('create-retentionrule-button');
  }

  getItemFromList(name: string) {
    return this.page.getByRole('listitem').filter({ hasText: name });
  }

  getPopoverButton(itemLocator: Locator) {
    return itemLocator.locator('button[aria-haspopup]');
  }

  getUpdateMenuItem() {
    return this.page.getByRole('menuitem', { name: 'Update' });
  }

  getActivateMenuItem() {
    return this.page.getByRole('menuitem', { name: 'Activate' });
  }

  getDeactivateMenuItem() {
    return this.page.getByRole('menuitem', { name: 'Deactivate' });
  }

  getDeleteMenuItem() {
    return this.page.getByRole('menuitem', { name: 'Delete' });
  }

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  getCancelDialogButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }

  getCloseDrawerButton() {
    return this.page.getByLabel('Close');
  }

  getDrawerUpdateButton() {
    return this.page.getByRole('button', { name: 'Update' });
  }

  getVerifyButton() {
    return this.page.getByRole('button', { name: 'Verify' });
  }

  getCreateFormButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getCancelFormButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}


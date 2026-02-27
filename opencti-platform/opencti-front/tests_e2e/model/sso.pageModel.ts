import { Page } from '@playwright/test';

export default class SSOPage {
  pageUrl = '/dashboard/settings/accesses/authentications';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    return this.page.getByTestId('authentication-page');
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create Authentication', exact: true }).click();
  }

  getCreateSAML() {
    return this.page.getByRole('menuitem', { name: 'Create SAML' }).click();
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }

  getSAMLConfig() {
    return this.page.getByText('e2e SSO Authentication');
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Update' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }
}

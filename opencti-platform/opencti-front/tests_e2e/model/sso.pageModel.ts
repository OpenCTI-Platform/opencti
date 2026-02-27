import { Page } from '@playwright/test';

export default class SSOPage {
  pageUrl = '/dashboard/settings/accesses/authentications';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    return this.page.getByTestId('sso-security-page');
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create authentication', exact: true });
  }

  getCreateSAML() {
    return this.page.getByRole('button', { name: 'Create SAML', exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}

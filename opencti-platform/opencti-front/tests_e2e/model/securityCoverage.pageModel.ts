import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class SecurityCoveragePage {
  pageUrl = '/dashboard/analyses/security_coverages';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Analyses', 'Security coverages');
  }

  getCreateButton() {
    return this.page.getByRole(
      'button',
      { name: 'Create Security Coverages', exact: true },
    );
  }

  openCreateForm() {
    return this.getCreateButton().click();
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}

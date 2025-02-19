// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class RolesSettingsPage {
  constructor(private page: Page) {}

  getSettingsPage() {
    return this.page.getByTestId('roles-settings-page');
  }

  getAddRoleButton() {
    return this.page.getByRole('button', { name: 'Create Role' });
  }

  getRoleInList(ruleName: string) {
    return this.page.getByRole('link', { name: ruleName });
  }
}

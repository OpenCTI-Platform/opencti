import { Page } from '@playwright/test';

export default class RolesSettingsPage {
  constructor(private page: Page) {}

  getSettingsPage() {
    return this.page.getByTestId('roles-settings-page');
  }

  getDetailsPage() {
    return this.page.getByTestId('role-details-page');
  }

  getAddRoleButton() {
    return this.page.getByRole('button', { name: 'Create Role' });
  }

  getRoleInList(ruleName: string) {
    return this.page.getByRole('link', { name: ruleName });
  }
}

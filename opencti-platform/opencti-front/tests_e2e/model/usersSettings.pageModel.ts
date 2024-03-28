// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class UsersSettingsPage {
  constructor(private page: Page) {}

  getSettingsPage() {
    return this.page.getByTestId('users-settings-page');
  }

  getAddUserButton() {
    return this.page.getByLabel('Add');
  }

  getUserInList(userName: string) {
    return this.page.getByRole('link', { name: userName });
  }
}

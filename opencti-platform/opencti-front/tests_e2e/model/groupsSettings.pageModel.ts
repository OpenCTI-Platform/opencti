import { Page } from '@playwright/test';

export default class GroupsSettingsPage {
  constructor(private page: Page) {}

  getSettingsPage() {
    return this.page.getByTestId('groups-settings-page');
  }

  getAddGroupButton() {
    return this.page.getByRole('button', { name: 'Create Group' });
  }

  getGroupInList(ruleName: string) {
    return this.page.getByRole('link', { name: ruleName });
  }
}

// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class GroupsSettingsPage {
  constructor(private page: Page) {}

  getSettingsPage() {
    return this.page.getByTestId('groups-settings-page');
  }

  getAddGroupButton() {
    return this.page.getByLabel('Add');
  }

  getGroupInList(ruleName: string) {
    return this.page.getByRole('link', { name: ruleName });
  }
}

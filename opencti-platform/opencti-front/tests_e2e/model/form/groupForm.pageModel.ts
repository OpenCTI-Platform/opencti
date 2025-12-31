import { Page } from '@playwright/test';

export default class GroupFormPage {
  constructor(private page: Page) {}

  getNameInput() {
    return this.page.getByLabel('Name');
  }

  async fillNameInput(name: string) {
    await this.getNameInput().click();
    return this.getNameInput().fill(name);
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getRolesTab() {
    return this.page.getByRole('tab', { name: 'Roles' });
  }

  getSpecificRuleCheckbox(ruleName: string) {
    return this.page.locator('li').filter({ hasText: ruleName }).getByRole('checkbox');
  }
}

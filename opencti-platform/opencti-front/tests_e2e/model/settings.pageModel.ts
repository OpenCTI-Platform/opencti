import { Page } from '@playwright/test';

export default class SettingsPage {
  constructor(private page: Page) {}

  getSettingsPage() {
    return this.page.getByTestId('settings-page');
  }

  getHiddenEntityTypeSelect() {
    return this.page.getByTestId('hiddenEntityTypes').getByLabel('');
  }

  getExternalReference() {
    return this.page.getByRole('option', { name: 'External reference' });
  }
}

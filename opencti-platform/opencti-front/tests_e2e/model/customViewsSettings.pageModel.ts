import { Locator, Page } from '@playwright/test';
import SettingsCustomizationPage from './settingsCustomization.pageModel';

export default class CustomViewsSettingsPage {
  constructor(private page: Page) {}

  async navigateFromMenu(customizationPage: SettingsCustomizationPage, entityTypeLabel: string) {
    await customizationPage.navigateFromMenu();
    await customizationPage.getItemFromList(entityTypeLabel).click();
    await this.page.getByRole('tab', { name: 'Custom Views', exact: true }).click();
  }

  getPageUrl(entityType: string) {
    return `/dashboard/settings/customization/entity_types/${entityType}/custom-views`;
  }

  getPageTitle() {
    return this.page.getByTestId('custom-views-page');
  }

  getAddButton() {
    return this.page.getByRole('button', { name: 'Create a new custom view' });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }

  getImportButton() {
    return this.page.getByRole('button', { name: 'Import a custom view' });
  }

  getQuickActionsButton(itemLocator: Locator) {
    return itemLocator.getByRole('button', { name: 'Custom view popover of actions' });
  }

  getDeleteQuickActionButton() {
    return this.page.getByRole('menuitem', { name: 'Delete' });
  }

  getEnableQuickActionButton() {
    return this.page.getByRole('menuitem', { name: 'Enable' });
  }

  getDisableQuickActionButton() {
    return this.page.getByRole('menuitem', { name: 'Disable' });
  }

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  getEmptyListMessage() {
    return this.page.getByText('No entries yet');
  }
}

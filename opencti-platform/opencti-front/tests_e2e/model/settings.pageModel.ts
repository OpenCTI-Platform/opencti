import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export type ManagerStatusFilter = 'all' | 'enabled' | 'disabled' | 'unlicensed';

export default class SettingsPage {
  pageUrl = '/dashboard/settings';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Settings');
    await leftBarPage.getSubItem('Parameters');
  }

  getPage() {
    return this.page.getByTestId('setting-page');
  }

  getPlatformSummary() {
    return this.page.getByTestId('settings-platform');
  }

  getPlatformFact(fact: 'version' | 'edition' | 'architecture' | 'nodes' | 'managers' | 'ai' | 'identifier') {
    return this.page.getByTestId(`settings-platform-${fact}`);
  }

  getConfigurationCard() {
    return this.page.getByTestId('settings-configuration');
  }

  getAppearanceCard() {
    return this.page.getByTestId('settings-appearance');
  }

  getDependencies() {
    return this.page.getByTestId('settings-dependencies').locator('[data-testid^="settings-dependency-"]');
  }

  getManagersCard() {
    return this.page.getByTestId('settings-managers');
  }

  getManagersFilter(status: ManagerStatusFilter) {
    return this.page.getByTestId(`settings-managers-filter-${status}`);
  }

  getManagersSearch() {
    return this.page.getByTestId('settings-managers-search');
  }

  getManagerGroups() {
    return this.getManagersCard().locator('[data-testid^="settings-managers-group-"]');
  }

  getManagerRows() {
    return this.getManagersCard().locator('li[data-testid^="settings-manager-"]');
  }

  getManagerRow(managerId: string) {
    return this.page.getByTestId(`settings-manager-${managerId}`);
  }

  getManagersEmptyState() {
    return this.page.getByTestId('settings-managers-empty');
  }
}

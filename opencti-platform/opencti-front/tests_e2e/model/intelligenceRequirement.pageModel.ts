import { expect, Page } from '@playwright/test';

/**
 * Screen of an intelligence requirement (/dashboard/intelligence_requirements/:id).
 * Every PIR is scored by its requirement and read on this screen: the PIR details page redirects here.
 */
export default class IntelligenceRequirementPageModel {
  constructor(private page: Page) {}

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getTab(name: string) {
    return this.page.getByRole('tab', { name: new RegExp(`^${name}`) });
  }

  async goToTab(name: string) {
    await this.getTab(name).click();
  }

  /** Base URL of the requirement, read from the current page once the PIR has redirected to it. */
  basePath() {
    const { pathname } = new URL(this.page.url());
    const match = pathname.match(/^(.*\/dashboard\/intelligence_requirements\/[^/]+)/);
    if (!match) throw new Error(`Not on an intelligence requirement screen: ${pathname}`);
    return match[1];
  }

  /**
   * Open the Entities tab and wait until its data is rendered: the type counters ('All (N)') come
   * from the network once the page has loaded, so a visibility check made right after goto reads an
   * empty screen.
   */
  async gotoEntities(basePath: string) {
    await this.page.goto(`${basePath}/entities`);
    await expect(this.page.getByRole('button', { name: /^All \(\d+\)$/ })).toBeVisible({ timeout: 30000 });
  }

  getEntity(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}

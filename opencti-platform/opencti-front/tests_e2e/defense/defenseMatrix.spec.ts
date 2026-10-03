import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

test.describe('Defense matrix', { tag: ['@ce'] }, () => {
  test('should display the matrix and the gaps tabs', async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    await page.goto('/dashboard/defense/matrix');
    await leftBarPage.expectBreadcrumb('Defense', 'Defense matrix');
    await expect(page.getByTestId('defense-matrix-tab')).toBeVisible();
    await expect(page.getByTestId('defense-matrix-status')).toBeVisible();

    await page.getByTestId('defense-tab-gaps').click();
    await expect(page).toHaveURL(/\/dashboard\/defense\/matrix\/gaps$/);
    await expect(page.getByTestId('defense-gaps-tab')).toBeVisible();

    await page.getByTestId('defense-tab-matrix').click();
    await expect(page.getByTestId('defense-matrix-tab')).toBeVisible();
  });

  test('should open the defense matrix from the attack patterns', async ({ page }) => {
    await page.goto('/dashboard/techniques/attack_patterns');
    await page.getByTestId('attack-patterns-open-defense-matrix').click();
    await expect(page).toHaveURL(/\/dashboard\/defense\/matrix$/);
    await expect(page.getByTestId('defense-matrix-tab')).toBeVisible();
  });

  test('should list the built-in telemetry mappings', async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    await page.goto('/dashboard/settings/customization/telemetry_mappings');
    await leftBarPage.expectBreadcrumb('Settings', 'Customization', 'Telemetry mappings');
    await expect(page.getByTestId('defense-logsource-mappings-page')).toBeVisible();
    await expect(page.getByTestId('defense-logsource-mappings-table')).toBeVisible();
    await expect(page.getByTestId('defense-logsource-mappings-create')).toBeVisible();
    await expect(page.getByTestId('defense-logsource-mappings-reset')).toBeVisible();
  });
});

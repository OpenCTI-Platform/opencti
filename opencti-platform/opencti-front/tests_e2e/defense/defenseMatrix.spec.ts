import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

test.describe('Defense matrix', { tag: ['@ce'] }, () => {
  test('should display the matrix and the gaps sections', async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    await page.goto('/dashboard/defense/matrix');
    await expect(page).toHaveURL(/\/dashboard\/defense\/matrix\/coverage$/);
    await leftBarPage.expectBreadcrumb('Defense', 'Defense matrix', 'Matrix');
    await expect(page.getByTestId('defense-matrix-tab')).toBeVisible();
    await expect(page.getByTestId('defense-matrix-status')).toBeVisible();
    await expect(page.getByTestId('defense-matrix-header')).toBeVisible();

    // The counters of the status header filter the matrix, a second click clears the filter
    const gapsCounter = page.getByTestId('defense-matrix-counter-gaps');
    await gapsCounter.click();
    await expect(gapsCounter).toHaveAttribute('aria-pressed', 'true');
    await gapsCounter.click();
    await expect(gapsCounter).toHaveAttribute('aria-pressed', 'false');

    await page.getByTestId('defense-matrix-section-gaps').click();
    await expect(page).toHaveURL(/\/dashboard\/defense\/matrix\/gaps$/);
    await leftBarPage.expectBreadcrumb('Defense', 'Defense matrix', 'Gaps');
    await expect(page.getByTestId('defense-gaps-tab')).toBeVisible();

    await page.getByTestId('defense-matrix-section-coverage').click();
    await expect(page.getByTestId('defense-matrix-tab')).toBeVisible();
  });

  test('should open the defense matrix from the attack patterns', async ({ page }) => {
    await page.goto('/dashboard/techniques/attack_patterns');
    await page.getByTestId('attack-patterns-open-defense-matrix').click();
    await expect(page).toHaveURL(/\/dashboard\/defense\/matrix\/coverage$/);
    await expect(page.getByTestId('defense-matrix-tab')).toBeVisible();
  });

  test('should list the built-in telemetry mappings', async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    await page.goto('/dashboard/settings/customization/telemetry_mappings');
    await leftBarPage.expectBreadcrumb('Settings', 'Customization', 'Telemetry mappings');
    await expect(page.getByTestId('defense-logsource-mappings-page')).toBeVisible();
    await expect(page.getByTestId('defense-logsource-mappings-first-use')).toBeVisible();
    await expect(page.getByTestId('defense-logsource-mappings-table')).toBeVisible();
    // On first use the creation action lives in the first-use card only
    await expect(page.getByTestId('defense-logsource-mappings-first-use-create')).toBeVisible();
    await expect(page.getByTestId('defense-logsource-mappings-create')).toBeHidden();
    await expect(page.getByTestId('defense-logsource-mappings-reset')).toBeVisible();
  });
});

import { expect, test } from '../fixtures/baseFixtures';
import SettingsPage from '../model/settings.pageModel';

/**
 * MUST show the platform summary, the configuration cards and the dependencies.
 * MUST name every manager (no raw id on screen) inside a domain group.
 * MUST filter the managers by status and by search, and offer a way back from an empty result.
 */
test('Parameters page summary, dependencies and managers grid', { tag: ['@ce'] }, async ({ page }) => {
  const settingsPage = new SettingsPage(page);
  await page.goto(settingsPage.pageUrl);
  await expect(settingsPage.getPage()).toBeVisible();

  await expect(settingsPage.getPlatformFact('version')).toBeVisible();
  await expect(settingsPage.getPlatformFact('edition')).toBeVisible();
  await expect(settingsPage.getPlatformFact('identifier')).toBeVisible();
  await expect(settingsPage.getConfigurationCard().getByLabel('Platform title')).toBeVisible();
  await expect(settingsPage.getAppearanceCard().getByRole('combobox', { name: 'Default theme' })).toBeVisible();
  await expect(settingsPage.getDependencies().first()).toBeVisible();

  const rows = settingsPage.getManagerRows();
  await expect(rows.first()).toBeVisible();
  const total = await rows.count();
  expect(await settingsPage.getManagerGroups().count()).toBeGreaterThan(0);
  for (const label of await rows.locator('p').allTextContents()) {
    expect(label).not.toMatch(/^[A-Z0-9]+(_[A-Z0-9]+)+$/);
  }
  await expect(settingsPage.getManagersFilter('all')).toContainText(`${total}`);
  await expect(settingsPage.getPlatformFact('managers')).toContainText(`of ${total} enabled`);

  // Search on the label, case insensitive
  await settingsPage.getManagersSearch().fill('HISTORY');
  await expect(rows).toHaveCount(1);
  await expect(settingsPage.getManagerRow('HISTORY_MANAGER')).toContainText('History manager');

  // A search with no match explains itself and resets both filters
  await settingsPage.getManagersSearch().fill('no manager is called like this');
  await expect(rows).toHaveCount(0);
  await expect(settingsPage.getManagersEmptyState()).toBeVisible();
  await settingsPage.getManagersEmptyState().getByRole('button', { name: 'Clear filters' }).click();
  await expect(rows).toHaveCount(total);
  await expect(settingsPage.getManagersSearch()).toHaveValue('');

  // Status filters only keep the managers of that status
  await settingsPage.getManagersFilter('enabled').click();
  await expect(settingsPage.getManagersFilter('enabled')).toHaveAttribute('aria-pressed', 'true');
  const enabledCount = await rows.count();
  await expect(rows.and(page.locator('[data-status="enabled"]'))).toHaveCount(enabledCount);
  await settingsPage.getManagersFilter('disabled').click();
  await expect(settingsPage.getManagersFilter('disabled')).toHaveAttribute('aria-pressed', 'true');
  const disabledCount = await rows.count();
  await expect(rows.and(page.locator('[data-status="disabled"]'))).toHaveCount(disabledCount);
  if (disabledCount === 0) {
    await expect(settingsPage.getManagersEmptyState()).toBeVisible();
  }
  // Without an Enterprise Edition license, the Enterprise-only managers have their own segment and the segments add up
  let unlicensedCount = 0;
  if (await settingsPage.getManagersFilter('unlicensed').isVisible()) {
    await settingsPage.getManagersFilter('unlicensed').click();
    await expect(settingsPage.getManagersFilter('unlicensed')).toHaveAttribute('aria-pressed', 'true');
    unlicensedCount = await rows.count();
    expect(unlicensedCount).toBeGreaterThan(0);
    await expect(rows.and(page.locator('[data-status="unlicensed"]'))).toHaveCount(unlicensedCount);
  }
  expect(enabledCount + disabledCount + unlicensedCount).toBe(total);
  await settingsPage.getManagersFilter('all').click();
  await expect(rows).toHaveCount(total);
});

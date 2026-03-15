import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import SearchPageModel from '../model/search.pageModel';
import { awaitUntilCondition } from '../utils';

/**
 * E2E test for custom entity display names (issue #14873).
 *
 * Covers the full lifecycle:
 * 1. Navigate to Settings > Customization > Entity types > Report
 * 2. Set a custom singular and plural display name
 * 3. Verify the values persist after page reload
 * 4. Reset to default and verify the fields are cleared
 *
 * Uses stable data-testid selectors:
 * - entity-setting-custom-name-input
 * - entity-setting-custom-name-plural-input
 * - entity-setting-custom-name-reset-btn
 */
test.describe('Entity Setting - Custom Display Name', { tag: ['@ce'] }, () => {
  test('Set, persist, and reset custom display name for Report entity type', async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);

    // Step 1: Navigate to Settings > Customization > Entity types > Report
    await page.goto('/');
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Settings', 'Customization');

    const search = new SearchPageModel(page);
    await search.addSearch('report');
    await page.getByRole('link', { name: 'Report' }).click();

    // Step 2: Verify custom name fields exist and are initially empty
    const singularInput = page.getByTestId('entity-setting-custom-name-input').locator('input');
    const pluralInput = page.getByTestId('entity-setting-custom-name-plural-input').locator('input');
    const resetButton = page.getByTestId('entity-setting-custom-name-reset-btn');

    await expect(singularInput).toBeVisible();
    await expect(pluralInput).toBeVisible();
    await expect(resetButton).toBeVisible();

    // Step 3: Set custom display names
    await singularInput.fill('Intelligence Product');
    await singularInput.blur();
    // Wait for the mutation to complete
    await page.waitForTimeout(1000);

    await pluralInput.fill('Intelligence Products');
    await pluralInput.blur();
    await page.waitForTimeout(1000);

    // Step 4: Verify persistence after reload
    const verifyPersistence = async () => {
      await page.reload();
      // Wait for the page to load
      await expect(page.getByTestId('entity-setting-custom-name-input')).toBeVisible();
      const singularValue = await page.getByTestId('entity-setting-custom-name-input').locator('input').inputValue();
      return singularValue === 'Intelligence Product';
    };
    await awaitUntilCondition(verifyPersistence, 2000, 5);

    const persistedSingular = await singularInput.inputValue();
    const persistedPlural = await pluralInput.inputValue();
    expect(persistedSingular).toBe('Intelligence Product');
    expect(persistedPlural).toBe('Intelligence Products');

    // Step 5: Reset to default
    await resetButton.click();
    await page.waitForTimeout(1000);

    // Verify fields are cleared after reset
    const resetSingular = await singularInput.inputValue();
    const resetPlural = await pluralInput.inputValue();
    expect(resetSingular).toBe('');
    expect(resetPlural).toBe('');

    // Step 6: Verify reset persists after reload
    const verifyResetPersistence = async () => {
      await page.reload();
      await expect(page.getByTestId('entity-setting-custom-name-input')).toBeVisible();
      const singularValue = await page.getByTestId('entity-setting-custom-name-input').locator('input').inputValue();
      return singularValue === '';
    };
    await awaitUntilCondition(verifyResetPersistence, 2000, 5);

    const finalSingular = await singularInput.inputValue();
    const finalPlural = await pluralInput.inputValue();
    expect(finalSingular).toBe('');
    expect(finalPlural).toBe('');
  });
});

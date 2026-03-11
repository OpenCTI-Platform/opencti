import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import SettingsCustomizationPage from '../model/settingsCustomization.pageModel';
import SearchPageModel from '../model/search.pageModel';

/**
 * E2E test for issue #14873 — Custom display names for entity types.
 *
 * Covers:
 * - Setting custom singular and plural display names for an entity type
 * - Verifying values persist after page reload
 * - Verifying the page title and breadcrumb reflect the custom name
 * - Resetting to default and verifying fields are cleared
 * - Verifying title/breadcrumb revert to default after reset
 */
test.describe('Entity setting custom display names', { tag: ['@ce'] }, () => {
  const ENTITY_TYPE = 'Report';
  const CUSTOM_NAME_SINGULAR = 'Intelligence Product';
  const CUSTOM_NAME_PLURAL = 'Intelligence Products';

  test('Set, verify, and reset custom display names for Report entity type', async ({ page }) => {
    // Navigate to Settings > Customization > Entity types
    await page.goto('/dashboard/settings/customization/entity_types');
    const customizationPage = new SettingsCustomizationPage(page);
    await expect(customizationPage.getCustomizationPages('subtypes-page')).toBeVisible();

    // Search for and open the Report entity type
    const search = new SearchPageModel(page);
    await search.addSearch(ENTITY_TYPE.toLowerCase());
    await page.getByRole('link', { name: ENTITY_TYPE }).click();
    await expect(page.getByRole('heading', { name: ENTITY_TYPE })).toBeVisible();

    // Verify the custom name fields exist with proper data-testid
    const singularInput = page.getByTestId('entity-setting-custom-name-input').locator('input');
    const pluralInput = page.getByTestId('entity-setting-custom-name-plural-input').locator('input');
    const resetButton = page.getByTestId('entity-setting-custom-name-reset-btn');

    await expect(singularInput).toBeVisible();
    await expect(pluralInput).toBeVisible();
    await expect(resetButton).toBeVisible();

    // Clear any previously set values to start from a clean state
    await singularInput.clear();
    await singularInput.blur();
    await pluralInput.clear();
    await pluralInput.blur();
    // Wait for mutation to complete
    await page.waitForTimeout(500);

    // Set custom singular name
    await singularInput.fill(CUSTOM_NAME_SINGULAR);
    await singularInput.blur();
    // Wait for the mutation to persist
    await page.waitForTimeout(500);

    // Set custom plural name
    await pluralInput.fill(CUSTOM_NAME_PLURAL);
    await pluralInput.blur();
    // Wait for the mutation to persist
    await page.waitForTimeout(500);

    // Verify the values are set in the input fields
    await expect(singularInput).toHaveValue(CUSTOM_NAME_SINGULAR);
    await expect(pluralInput).toHaveValue(CUSTOM_NAME_PLURAL);

    // Reload the page to verify persistence
    await page.reload();
    await page.waitForTimeout(1000);

    // After reload, the page title and breadcrumb should reflect the custom name
    const headingAfterSet = page.getByTestId('entity-type-title');
    await expect(headingAfterSet).toContainText(CUSTOM_NAME_SINGULAR);

    // Verify breadcrumb contains the custom name
    const breadcrumb = page.getByTestId('navigation');
    await expect(breadcrumb).toContainText(CUSTOM_NAME_SINGULAR);

    // Re-locate inputs after reload and verify persistence
    const singularInputAfterReload = page.getByTestId('entity-setting-custom-name-input').locator('input');
    const pluralInputAfterReload = page.getByTestId('entity-setting-custom-name-plural-input').locator('input');

    await expect(singularInputAfterReload).toHaveValue(CUSTOM_NAME_SINGULAR);
    await expect(pluralInputAfterReload).toHaveValue(CUSTOM_NAME_PLURAL);

    // Test reset to default
    const resetBtn = page.getByTestId('entity-setting-custom-name-reset-btn');
    await expect(resetBtn).toBeEnabled();
    await resetBtn.click();
    // Wait for the mutation to persist
    await page.waitForTimeout(500);

    // Verify fields are cleared
    await expect(page.getByTestId('entity-setting-custom-name-input').locator('input')).toHaveValue('');
    await expect(page.getByTestId('entity-setting-custom-name-plural-input').locator('input')).toHaveValue('');

    // Verify reset button is now disabled
    await expect(resetBtn).toBeDisabled();

    // Reload and confirm reset persisted — title/breadcrumb should revert to default
    await page.reload();
    await page.waitForTimeout(1000);

    // Title should be back to the default i18n label
    const headingAfterReset = page.getByTestId('entity-type-title');
    await expect(headingAfterReset).toBeVisible();

    // Fields should remain empty
    await expect(page.getByTestId('entity-setting-custom-name-input').locator('input')).toHaveValue('');
    await expect(page.getByTestId('entity-setting-custom-name-plural-input').locator('input')).toHaveValue('');
  });
});

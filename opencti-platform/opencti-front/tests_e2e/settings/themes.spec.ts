import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';
import { awaitUntilCondition } from 'tests_e2e/utils';

const openThemeEditMenu = async (themeName: string, page: Page) => {
  await page
    .getByTestId(`${themeName}-popover`)
    .click();
  await page
    .getByRole('menuitem', { name: 'Update' })
    .click();
};

/**
 * Edits the logo URL of a theme through the edition drawer.
 * The logo field is persisted on blur, so we explicitly blur the input and
 * wait for the update to complete before closing the drawer. Otherwise a
 * subsequent navigation/reload could abort the in-flight mutation and the
 * change would never be persisted.
 */
const editThemeLogo = async (themeName: string, page: Page, logoUrl: string) => {
  await openThemeEditMenu(themeName, page);
  const logoInput = page.locator('input[name="theme_logo"]');
  await logoInput.fill(logoUrl);
  await logoInput.blur();
  await expect(page.getByText('Successfully updated theme').first()).toBeVisible();
  for (const closeBtn of await page.getByLabel('Close').all()) {
    await closeBtn.click();
  }
};

/**
 * MUST create custom theme.
 * MUST check visibility in list lines.
 * MUST select custom theme and validate its usage.
 * MUST edit custom theme.
 * MUST change custom theme logo.
 * MUST delete custom theme.
 */
test('Custom theme creation, logo edition, and deletion', { tag: ['@ce'] }, async ({ page, request }) => {
  const THEME = {
    name: `${new Date().toISOString()} Test Theme`,
    theme_background: '#e72a2a',
    theme_paper: '#8f3939',
    theme_nav: '#bb4545',
    theme_primary: '#460707',
    theme_secondary: '#b88f8f',
    theme_accent: '#5d4e4e',
    theme_text_color: '#353131',
    theme_logo: 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png',
  };

  // Capture the current default theme to restore it whatever happens to the test:
  // the platform theme is a platform-wide state shared with every other test
  const settings = await getSettings(request);
  const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');

  // Navigate to Settings
  const leftBarPage = new LeftBarPage(page);
  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  // Create theme
  await page.getByTestId('create-theme-btn').click();

  // disable on purpose because we want that fill to be sequentially

  for (const [key, value] of Object.entries(THEME)) {
    await page.locator(`input[name="${key}"]`).fill(value);
  }

  await page.getByRole('button', { name: 'Create' }).click();

  // Assert exists on screen
  // The library Select mirrors every theme name into a hidden native <option>, which comes first in the DOM.
  await expect(page.getByText(THEME.name).filter({ visible: true }).first()).toBeVisible();

  const logoImage = page.getByRole('link', { name: 'logo' }).locator('img');
  let logoSrc = await logoImage.getAttribute('src');
  expect(logoSrc).toContain('googlelogo');

  try {
    // Select system default
    await page.getByRole('combobox', { name: 'Default theme' }).click();
    await page.getByTestId(`${THEME.name}-li`).click();

    // Edit theme
    // edit the logo url by removing the url, expect to be back on the default dark logo
    await editThemeLogo(THEME.name, page, '');
    await expect(logoImage).toHaveAttribute('src', /logo_text_dark/);

    // Set theme logo to the Google logo
    await editThemeLogo(THEME.name, page, THEME.theme_logo);
    const isLogoChanged = async () => {
      await page.reload();
      const logoSrcChangedToGoogle = await logoImage.getAttribute('src');
      if (logoSrcChangedToGoogle) {
        return logoSrcChangedToGoogle.includes('googlelogo');
      }
      return false;
    };
    await awaitUntilCondition(isLogoChanged);
    await expect(logoImage).toHaveAttribute('src', /googlelogo/);

    // Reset logo
    await editThemeLogo(THEME.name, page, '');
    const isLogoBackToDefault = async () => {
      await page.reload();
      const logoSrcChangedToDefault = await logoImage.getAttribute('src');
      if (logoSrcChangedToDefault) {
        return logoSrcChangedToDefault.includes('logo_text_dark');
      }
      return false;
    };
    await awaitUntilCondition(isLogoBackToDefault);
    await expect(logoImage).toHaveAttribute('src', /logo_text_dark/);
  } finally {
    // Restore the default theme through the API: an awaited call cannot be aborted by the
    // page closing at the end of the test, and it also runs when an assertion failed
    // mid-test, so the platform theme cannot leak to other tests
    await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
  }

  // Set theme logo to the Google logo
  await editThemeLogo(THEME.name, page, THEME.theme_logo);
  const isLogoChanged = async () => {
    await page.reload();
    const logoSrcChangedToGoogle = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
    if (logoSrcChangedToGoogle) {
      return logoSrcChangedToGoogle.includes('googlelogo');
    }
    return false;
  };
  await awaitUntilCondition(isLogoChanged);

  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('googlelogo');

  // Reset logo
  await editThemeLogo(THEME.name, page, '');
  await page.waitForTimeout(1000);

  const isLogoBackToDefault = async () => {
    await page.reload();
    const logoSrcChangedToDefault = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
    if (logoSrcChangedToDefault) {
      return logoSrcChangedToDefault.includes('logo_text_dark');
    }
    return false;
  };
  await awaitUntilCondition(isLogoBackToDefault);
  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('logo_text_dark');

  // Select Dark theme again to delete custom theme
  // The default-theme field is on the library Select now, so the MUI-generated
  // `#mui-component-select-<name>` id is gone. Targeted by its accessible role
  // and name instead, which is what a user and a screen reader both use.
  await page.getByRole('combobox', { name: 'Default theme' }).click();
  await page.getByTestId('Filigran Dark-li').click();
  await page.waitForTimeout(1000);
  // Reload so the UI is back on the restored theme before deleting the custom one
  await page.reload();

  // Delete custom theme
  await page.getByTestId(`${THEME.name}-popover`).click();
  await page.getByLabel('Delete').click();
  await page.getByRole('button', { name: 'Confirm' }).click();
  // The snackbar also keeps the page open until the delete mutation completes
  await expect(page.getByText('Theme successfully deleted')).toBeVisible();
});

/**
 * MUST ensure cannot delete system theme.
 * MUST ensure cannot update system theme.
 */
test('Cannot delete or update system theme', { tag: ['@ce'] }, async ({ page }) => {
  // Navigate to Settings
  const leftBarPage = new LeftBarPage(page);
  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  await page.getByTestId('Filigran Light-popover').click();
  // A built-in theme only offers View and Export in its popover
  await expect(page.getByRole('menuitem', { name: 'View' })).toBeVisible();
  await expect(page.getByRole('menuitem', { name: 'Update' })).toHaveCount(0);
  await expect(page.getByRole('menuitem', { name: 'Delete' })).toHaveCount(0);
  expect(await page.getByLabel('Update').count()).toBe(0);
});

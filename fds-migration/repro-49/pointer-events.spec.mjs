// Diagnostic for LIBRARY-FEEDBACK #49.
//
// Question, binary: does the design system leave `pointer-events: none` on
// <body> after a panel closes, and on which close path exactly.
//
// Radix's react-dismissable-layer is the only writer of that property. It sets
// it when `disableOutsidePointerEvents` is true and restores it on cleanup. The
// library's Combobox mounts PopoverPrimitive.Root with `modal: false`, which
// never reaches that code; its Select mounts SelectPrimitive.Root, which does.
// So the two components are measured separately and the expectation differs.
import { test, expect } from '@playwright/test';

const URL = 'http://localhost:4300/';
const bodyPE = (page) => page.evaluate(() => ({
  computed: getComputedStyle(document.body).pointerEvents,
  inline: document.body.style.pointerEvents || '',
}));

for (const theme of ['dark', 'light']) {
  test.describe(`theme: ${theme}`, () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(URL);
      await expect(page.locator('#sel-trigger')).toBeVisible();
      if (theme === 'light') await page.locator('#toggle-theme').click();
      const before = await bodyPE(page);
      expect(before.computed, 'baseline must be clean').toBe('auto');
    });

    // ---- library Select: Radix Select IS modal, body is expected to be
    // touched while open and RESTORED on every close path.
    test('select — close by selecting an option', async ({ page }) => {
      await page.locator('#sel-trigger').click();
      await expect(page.getByRole('listbox')).toBeVisible();
      const open = await bodyPE(page);
      await page.getByRole('option', { name: 'Bravo' }).click();
      await expect(page.getByRole('listbox')).toBeHidden();
      const after = await bodyPE(page);
      console.log(`[select/select] open=${JSON.stringify(open)} after=${JSON.stringify(after)}`);
      expect(after.computed).toBe('auto');
      await page.locator('#after-button').click({ timeout: 5000 });
    });

    test('select — close by Escape', async ({ page }) => {
      await page.locator('#sel-trigger').click();
      await expect(page.getByRole('listbox')).toBeVisible();
      const open = await bodyPE(page);
      await page.keyboard.press('Escape');
      await expect(page.getByRole('listbox')).toBeHidden();
      const after = await bodyPE(page);
      console.log(`[select/escape] open=${JSON.stringify(open)} after=${JSON.stringify(after)}`);
      expect(after.computed).toBe('auto');
      await page.locator('#after-button').click({ timeout: 5000 });
    });

    test('select — close by clicking outside', async ({ page }) => {
      await page.locator('#sel-trigger').click();
      await expect(page.getByRole('listbox')).toBeVisible();
      const open = await bodyPE(page);
      await page.mouse.click(5, 5);
      await expect(page.getByRole('listbox')).toBeHidden();
      const after = await bodyPE(page);
      console.log(`[select/outside] open=${JSON.stringify(open)} after=${JSON.stringify(after)}`);
      expect(after.computed).toBe('auto');
      await page.locator('#after-button').click({ timeout: 5000 });
    });

    test('select — close by Tab blur', async ({ page }) => {
      await page.locator('#sel-trigger').click();
      await expect(page.getByRole('listbox')).toBeVisible();
      const open = await bodyPE(page);
      await page.keyboard.press('Tab');
      const after = await bodyPE(page);
      console.log(`[select/tab] open=${JSON.stringify(open)} after=${JSON.stringify(after)}`);
      expect(after.computed).toBe('auto');
      await page.locator('#after-button').click({ timeout: 5000 });
    });

    test('select — unmounted while open', async ({ page }) => {
      await page.locator('#sel-trigger').click();
      await expect(page.getByRole('listbox')).toBeVisible();
      const open = await bodyPE(page);
      // Unmount the field with its panel still open — the case a product hits
      // when a drawer closes, a route changes, or a conditional flips.
      await page.evaluate(() => document.querySelector('#unmount-select').click());
      const after = await bodyPE(page);
      console.log(`[select/unmount] open=${JSON.stringify(open)} after=${JSON.stringify(after)}`);
      expect(after.computed).toBe('auto');
      await page.locator('#after-button').click({ timeout: 5000 });
    });

    // ---- library Combobox: modal:false, so body must NEVER be touched at all.
    test('combobox — body untouched on every path', async ({ page }) => {
      const paths = [];
      await page.locator('#cbx-input').click();
      await expect(page.getByRole('listbox')).toBeVisible();
      paths.push(['open', await bodyPE(page)]);
      await page.getByRole('option', { name: 'Charlie' }).click();
      paths.push(['after select', await bodyPE(page)]);
      await page.locator('#cbx-input').click();
      await page.keyboard.press('Escape');
      paths.push(['after escape', await bodyPE(page)]);
      await page.locator('#cbx-input').click();
      await page.mouse.click(5, 5);
      paths.push(['after outside', await bodyPE(page)]);
      await page.locator('#cbx-input').click();
      await page.keyboard.press('Tab');
      paths.push(['after tab', await bodyPE(page)]);
      await page.locator('#cbx-input').click();
      await page.evaluate(() => document.querySelector('#unmount-cbx').click());
      paths.push(['after unmount', await bodyPE(page)]);
      console.log(`[combobox] ${paths.map(([k, v]) => `${k}=${v.computed}`).join(' | ')}`);
      for (const [k, v] of paths) expect(v.computed, `combobox ${k}`).toBe('auto');
      await page.locator('#after-button').click({ timeout: 5000 });
    });
  });
}

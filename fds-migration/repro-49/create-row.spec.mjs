import { test, expect } from '@playwright/test';
// Does onCreateOption still render a `Create '<x>'` row when filterOptions is
// the identity function? incidentResponse fails clicking exactly that row on
// ExternalReferencesField, which uses an identity filter for its server search.
for (const [name, id, label] of [
  ['identity filterOptions', '#idf-input', 'Identity filter'],
  ['default filtering (control)', '#dflt-input', 'Default filter'],
]) {
  test(`create row — ${name}`, async ({ page }) => {
    await page.goto('http://localhost:4300/');
    await page.locator(id).click();
    await page.locator(id).fill('brand new value');
    await page.waitForTimeout(500);
    const rows = await page.evaluate(() => {
      const lb = document.querySelector('[role="listbox"]');
      return {
        listbox: !!lb,
        options: lb ? [...lb.querySelectorAll('[role="option"]')].map((o) => o.textContent.trim()) : [],
      };
    });
    console.log(`  [${name}] listbox=${rows.listbox} options=${JSON.stringify(rows.options)}`);
    const createRow = rows.options.find((o) => /create/i.test(o));
    console.log(`  [${name}] create row: ${createRow ? JSON.stringify(createRow) : 'ABSENT'}`);
  });
}

import { test, expect } from '@playwright/test';
// Exactly the matcher from AutocompleteField.pageModel.createOption, against a
// one-word value (report.spec, passes on CI) and a multi-word value
// (incidentResponse, times out on CI).
for (const value of ['external ref', 'external ref incident response']) {
  test(`createOption matcher — ${JSON.stringify(value)}`, async ({ page }) => {
    await page.goto('http://localhost:4300/');
    await page.locator('#idf-input').click();
    await page.locator('#idf-input').fill(value);
    await page.waitForTimeout(400);
    const raw = await page.evaluate(() => {
      const lb = document.querySelector('[role="listbox"]');
      return lb ? [...lb.querySelectorAll('[role="option"]')].map((o) => JSON.stringify(o.textContent)) : [];
    });
    console.log(`  rows: ${raw.join(' | ')}`);
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`Create\\s*\\S?${escaped}`);
    const list = page.getByRole('listbox', { name: 'Identity filter' });
    const n = await list.getByText(re).count();
    console.log(`  regex ${re} -> matches: ${n}`);
    let err = null;
    try { await list.getByText(re).click({ timeout: 4000 }); } catch (e) { err = e.message.split('\n')[0].replace('locator.click: ', ''); }
    console.log(`  click: ${err || 'SUCCEEDED'}`);
  });
}

// Local layout captures of the standalone pull request at 1440x900 and 1920x1080; never committed.
import { expect, test } from '../fixtures/baseFixtures';
import { addIntrusionSet, deleteIntrusionSet, openProposalIds } from '../dataForTesting/curation.data';

const OUT = 'C:/Users/SamuelHassine/AppData/Local/Temp/octi-innov/s05-layout';

test('layout captures of the curation surfaces', async ({ page, request }) => {
  test.setTimeout(400000);
  const suffix = `${Math.floor(1000 + Math.random() * 9000)}`;
  const firstId = await addIntrusionSet(request, `Amber Heron ${suffix}`);
  const secondId = await addIntrusionSet(request, `amber-heron ${suffix}`);
  try {
    await expect.poll(async () => (await openProposalIds(request, firstId)).length, { timeout: 240000, intervals: [5000] }).toBeGreaterThan(0);
    const [proposalId] = await openProposalIds(request, firstId);
    const surfaces: Array<[string, string, string]> = [
      ['inbox', '/dashboard/data/curation/inbox', `Amber Heron ${suffix}`],
      ['proposal', `/dashboard/data/curation/inbox/${proposalId}`, 'Recommendation'],
      ['merges', '/dashboard/data/curation/merges', 'Merges'],
      ['health', '/dashboard/data/curation/health', 'Knowledge health'],
      ['settings', '/dashboard/settings/customization/curation/settings', 'Detection'],
      ['policies', '/dashboard/settings/customization/curation/policies', 'Policies'],
    ];
    for (const [width, height] of [[1440, 900], [1920, 1080]]) {
      await page.setViewportSize({ width, height });
      for (const [name, url, text] of surfaces) {
        await page.goto(url);
        await expect(page.getByText(text).first()).toBeVisible();
        await expect(page.locator('.MuiSkeleton-root')).toHaveCount(0, { timeout: 30000 });
        await page.waitForTimeout(800);
        await page.screenshot({ path: `${OUT}/curation-${name}-${width}.png` });
      }
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/dashboard/data/entities');
    await page.getByTestId('ExpandMoreIcon').first().waitFor({ state: 'attached', timeout: 5000 }).catch(() => {});
  } finally {
    await deleteIntrusionSet(request, secondId);
    await deleteIntrusionSet(request, firstId);
  }
});

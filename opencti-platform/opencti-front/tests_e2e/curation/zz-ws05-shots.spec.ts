// Local captures of the standalone pull request (layout set at 1440 and 1920, explanation set), dark and light; never committed.
import type { APIRequestContext, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import { addIntrusionSet, deleteIntrusionSet, openProposalIds } from '../dataForTesting/curation.data';
import { graphqlQuery } from '../dataForTesting/query-utils';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';

const LAYOUT = 'C:/Users/SamuelHassine/AppData/Local/Temp/octi-innov/s05-shots/layout';
const DOCS = 'C:/Users/SamuelHassine/AppData/Local/Temp/octi-innov/s05-shots/docs';

const addWith = async (request: APIRequestContext, input: Record<string, unknown>) => {
  const fields = Object.entries(input).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join(', ');
  const response = await (await graphqlQuery(request, `mutation { intrusionSetAdd(input: { ${fields} }) { id } }`)).json();
  return response.data.intrusionSetAdd.id as string;
};

const proposalsOf = async (request: APIRequestContext, id: string) => {
  const query = `query { curationProposalsForEntity(id: "${id}") { id proposal_kind proposal_status } }`;
  const proposals = await (await graphqlQuery(request, query)).json();
  return (proposals.data.curationProposalsForEntity ?? []) as Array<{ id: string; proposal_kind: string; proposal_status: string }>;
};

const settle = async (page: Page) => {
  await expect(page.locator('.MuiSkeleton-root')).toHaveCount(0, { timeout: 30000 });
  await page.waitForTimeout(900);
};

test('captures of the standalone curation surfaces', async ({ page, request }) => {
  test.setTimeout(1200000);
  const settings = await getSettings(request);
  const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
  const themes: Array<[string, string]> = [
    ['dark', await getThemeIdByName(request, 'Filigran Dark')],
    ['light', await getThemeIdByName(request, 'Filigran Light')],
  ];
  const suffix = `${Math.floor(1000 + Math.random() * 9000)}`;
  const firstId = await addIntrusionSet(request, `Amber Heron ${suffix}`);
  const secondId = await addIntrusionSet(request, `amber-heron ${suffix}`);
  const apt28 = await addWith(request, { name: 'APT28', aliases: ['Sofacy'], description: 'Russian threat actor attributed to the GRU.' });
  const fancyBear = await addWith(request, { name: 'Fancy Bear', description: 'Threat actor tracked under several vendor names.' });
  try {
    await expect.poll(async () => (await openProposalIds(request, firstId)).length, { timeout: 300000, intervals: [5000] }).toBeGreaterThan(0);
    await expect.poll(async () => (await openProposalIds(request, apt28)).length, { timeout: 300000, intervals: [5000] }).toBeGreaterThan(1);
    const [proposalId] = await openProposalIds(request, firstId);
    const apt28Proposals = (await proposalsOf(request, apt28)).filter((proposal) => proposal.proposal_status === 'open');
    const alias = apt28Proposals.find((proposal) => proposal.proposal_kind === 'alias');
    const merge = apt28Proposals.find((proposal) => proposal.proposal_kind !== 'alias');
    console.log(`proposals of APT28: ${apt28Proposals.map((proposal) => proposal.proposal_kind).join(', ')}`);
    const surfaces: Array<[string, string, string]> = [
      ['inbox', '/dashboard/data/curation/inbox', `Amber Heron ${suffix}`],
      ['proposal', `/dashboard/data/curation/inbox/${proposalId}`, 'Recommendation'],
      ['merges', '/dashboard/data/curation/merges', 'Merges'],
      ['health', '/dashboard/data/curation/health', 'Knowledge health'],
      ['settings', '/dashboard/settings/customization/curation/settings', 'Detection'],
      ['policies', '/dashboard/settings/customization/curation/policies', 'Policies'],
    ];
    for (const [theme, themeId] of themes) {
      await patchSettings(request, settings.id, 'platform_theme', themeId);
      const docsSuffix = theme === 'light' ? '-light' : '';
      for (const [width, height] of [[1440, 900], [1920, 1080]]) {
        await page.setViewportSize({ width, height });
        for (const [name, url, text] of surfaces) {
          await page.goto(url);
          await expect(page.getByText(text).first()).toBeVisible();
          await settle(page);
          await page.screenshot({ path: `${LAYOUT}/curation-${name}-${width}-${theme}.jpg`, type: 'jpeg', quality: 85 });
        }
        // The Data menu expanded: Curation right after Relationships, with its pending count; nothing under Defense.
        await page.evaluate(() => {
          localStorage.setItem('navOpen', 'true');
          localStorage.setItem('selectedMenu', JSON.stringify(['data']));
        });
        await page.goto('/dashboard/data/curation/inbox');
        await expect(page.getByText(`Amber Heron ${suffix}`).first()).toBeVisible();
        await settle(page);
        await page.screenshot({ path: `${LAYOUT}/curation-menu-${width}-${theme}.jpg`, type: 'jpeg', quality: 85 });
        await page.evaluate(() => {
          localStorage.setItem('navOpen', 'false');
          localStorage.setItem('selectedMenu', '[]');
        });
      }
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.goto(`/dashboard/threats/intrusion_sets/${apt28}`);
      await expect(page.getByTestId('curation-possible-duplicate')).toBeVisible();
      await settle(page);
      await page.screenshot({ path: `${DOCS}/curation-explanation-after-entity-header${docsSuffix}.png`, clip: { x: 0, y: 0, width: 1440, height: 360 } });
      for (const [kind, proposal] of [['alias', alias], ['merge', merge]] as const) {
        if (!proposal) continue;
        await page.goto(`/dashboard/data/curation/inbox/${proposal.id}`);
        await expect(page.getByTestId('curation-proposal-page')).toBeVisible();
        await settle(page);
        await page.screenshot({ path: `${DOCS}/curation-explanation-after-${kind}-page${docsSuffix}.png` });
        await page.getByTestId('curation-proposal-review').click();
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible();
        await page.waitForTimeout(800);
        await dialog.screenshot({ path: `${DOCS}/curation-explanation-after-${kind}-dialog${docsSuffix}.png` });
        await page.keyboard.press('Escape');
      }
    }
  } finally {
    await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
    for (const id of [fancyBear, apt28, secondId, firstId]) {
      await deleteIntrusionSet(request, id);
    }
  }
});

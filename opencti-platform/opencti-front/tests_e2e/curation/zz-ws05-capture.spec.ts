// Local captures of the standalone pull request at 1440x900 and 1920x1080, dark and light; never committed.
import type { APIRequestContext, Page } from '@playwright/test';
import { expect, test } from '../fixtures/secondUserFixtures';
import CurationPage from '../model/curation.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import { addIntrusionSet, deleteIntrusionSet, mergeIntrusionSets, openProposalIds } from '../dataForTesting/curation.data';
import { graphqlQuery } from '../dataForTesting/query-utils';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';
import { addRoles } from '../dataForTesting/role.data';
import { addGroups } from '../dataForTesting/group.data';
import { addUsers } from '../dataForTesting/user.data';
import { REGISTER_BANNER_DISMISSED_KEY } from '../../src/utils/bannerConstants';

const OUT = 'C:/Users/SamuelHassine/AppData/Local/Temp/octi-innov/s05/shots';
const SIZES: Array<[number, number]> = [[1440, 900], [1920, 1080]];

const settle = async (page: Page) => {
  await expect(page.locator('.MuiSkeleton-root')).toHaveCount(0, { timeout: 30000 });
  await page.waitForTimeout(1000);
};

const shot = async (page: Page, name: string, width: number, theme: string) => {
  await page.screenshot({ path: `${OUT}/curation-${name}-${width}-${theme}.jpg`, type: 'jpeg', quality: 82 });
};

const refreshHealth = async (request: APIRequestContext) => {
  await graphqlQuery(request, 'mutation { knowledgeHealthRefresh { id } }');
};

// A new user also joins the default groups, whose role grants the knowledge access: only the given group is kept.
const keepOnlyGroup = async (request: APIRequestContext, email: string, groupName: string) => {
  const query = `query { users(search: "${email}") { edges { node { id user_email groups { edges { node { id name } } } } } } }`;
  const users = await (await graphqlQuery(request, query)).json();
  type Node = { id: string; user_email: string; groups: { edges: Array<{ node: { id: string; name: string } }> } };
  const user = (users.data.users.edges as Array<{ node: Node }>).map((edge) => edge.node).find((node) => node.user_email === email);
  if (!user) throw new Error(`user ${email} not found`);
  for (const { node } of user.groups.edges) {
    if (node.name !== groupName) {
      await graphqlQuery(request, `mutation { userEdit(id: "${user.id}") { relationDelete(toId: "${node.id}", relationship_type: "member-of") { id } } }`);
    }
  }
};

test('captures of the standalone curation surfaces', async ({ page, request, secondUserPage }) => {
  test.setTimeout(1500000);
  page.setDefaultTimeout(60000);
  page.setDefaultNavigationTimeout(60000);
  const curation = new CurationPage(page);
  const settings = await getSettings(request);
  const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
  const themes: Array<[string, string]> = [
    ['dark', await getThemeIdByName(request, 'Filigran Dark')],
    ['light', await getThemeIdByName(request, 'Filigran Light')],
  ];
  const suffix = `${Math.floor(1000 + Math.random() * 9000)}`;
  const duplicateId = await addIntrusionSet(request, `Amber Heron ${suffix}`);
  const duplicateTwinId = await addIntrusionSet(request, `amber-heron ${suffix}`);
  const mergedName = `Teal Osprey ${suffix}`;
  const mergedId = await addIntrusionSet(request, mergedName);
  const absorbedId = await addIntrusionSet(request, `Teal Osprey Group ${suffix}`);
  await mergeIntrusionSets(request, mergedId, absorbedId);
  await addRoles(request, [{ name: 'Curation e2e no knowledge', capabilities: [] }]);
  await addGroups(request, [{ name: 'Curation e2e no knowledge', roles: ['Curation e2e no knowledge'] }]);
  await addUsers(request, [{ name: 'Curation reader', user_email: 'curation.reader@filigran.test', password: 'curationreader', groups: ['Curation e2e no knowledge'] }]);
  await keepOnlyGroup(request, 'curation.reader@filigran.test', 'Curation e2e no knowledge');
  try {
    await expect.poll(async () => (await openProposalIds(request, duplicateId)).length, { timeout: 300000, intervals: [5000] }).toBeGreaterThan(0);
    const [proposalId] = await openProposalIds(request, duplicateId);
    await refreshHealth(request);

    await secondUserPage.goto('/');
    await secondUserPage.evaluate((key) => localStorage.setItem(key, 'true'), REGISTER_BANNER_DISMISSED_KEY);
    await new LoginFormPageModel(secondUserPage).login('curation.reader@filigran.test', 'curationreader');
    await expect(secondUserPage.getByTestId('login-page')).toBeHidden();

    for (const [theme, themeId] of themes) {
      await patchSettings(request, settings.id, 'platform_theme', themeId);
      for (const [width, height] of SIZES) {
        await page.setViewportSize({ width, height });

        await page.goto('/dashboard/data/curation/inbox');
        await expect(page.getByText(`Amber Heron ${suffix}`).first()).toBeVisible();
        await settle(page);
        await shot(page, 'inbox', width, theme);

        await page.goto(`/dashboard/data/curation/inbox/${proposalId}`);
        await expect(page.getByTestId('curation-proposal-page')).toBeVisible();
        await settle(page);
        await shot(page, 'proposal', width, theme);

        await page.goto('/dashboard/data/curation/merges');
        await expect(curation.getMerges().getByText(mergedName).first()).toBeVisible();
        await settle(page);
        await shot(page, 'merges', width, theme);
        await curation.getMerges().getByText(mergedName).first().click();
        await expect(curation.getMergeRecordDetails()).toBeVisible();
        await settle(page);
        await shot(page, 'merge-record', width, theme);
        await page.keyboard.press('Escape');

        await page.goto('/dashboard/data/curation/health');
        await expect(curation.getKnowledgeHealth()).toBeVisible();
        await settle(page);
        await shot(page, 'health', width, theme);

        await page.goto('/dashboard/settings/customization/curation/settings');
        await expect(curation.getSettings()).toBeVisible();
        await settle(page);
        await shot(page, 'settings', width, theme);

        await page.goto('/dashboard/settings/customization/curation/policies');
        await expect(curation.getPolicies()).toBeVisible();
        await curation.waitForPoliciesLoaded();
        await settle(page);
        await shot(page, 'policies', width, theme);

        // The Data menu expanded: Curation right after Relationships, with its pending count.
        await page.evaluate(() => {
          localStorage.setItem('navOpen', 'true');
          localStorage.setItem('selectedMenu', JSON.stringify(['data']));
        });
        await page.goto('/dashboard/data/curation/inbox');
        await expect(page.getByText(`Amber Heron ${suffix}`).first()).toBeVisible();
        await settle(page);
        await shot(page, 'menu', width, theme);
        await page.evaluate(() => {
          localStorage.setItem('navOpen', 'false');
          localStorage.setItem('selectedMenu', '[]');
        });

        await secondUserPage.setViewportSize({ width, height });
        await secondUserPage.goto('/dashboard/data/curation');
        await expect(secondUserPage.getByTestId('hub-no-access')).toBeVisible();
        await secondUserPage.waitForTimeout(1000);
        await secondUserPage.screenshot({ path: `${OUT}/curation-no-access-${width}-${theme}.jpg`, type: 'jpeg', quality: 82 });
      }
    }
  } finally {
    await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
    for (const id of [mergedId, duplicateTwinId, duplicateId]) {
      await deleteIntrusionSet(request, id);
    }
  }
});

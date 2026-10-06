// Local captures of the explanation of an alias proposal for the user guide; never committed.
import { expect, test } from '../fixtures/baseFixtures';
import { deleteIntrusionSet, openProposalIds } from '../dataForTesting/curation.data';
import { graphqlQuery } from '../dataForTesting/query-utils';

const OUT = 'C:/Users/SamuelHassine/AppData/Local/Temp/octi-innov/s05-explanation';

test.use({ viewport: { width: 1440, height: 1000 } });

test('explanation captures of an alias proposal', async ({ page, request }) => {
  test.setTimeout(400000);
  const add = async (input: Record<string, unknown>) => {
    const fields = Object.entries(input).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join(', ');
    const response = await (await graphqlQuery(request, `mutation { intrusionSetAdd(input: { ${fields} }) { id } }`)).json();
    return response.data.intrusionSetAdd.id as string;
  };
  const apt28 = await add({ name: 'APT28', aliases: ['Sofacy'], description: 'Russian threat actor attributed to the GRU.' });
  const fancyBear = await add({ name: 'Fancy Bear', description: 'Threat actor tracked under several vendor names.' });
  try {
    await expect.poll(async () => (await openProposalIds(request, apt28)).length, { timeout: 240000, intervals: [5000] }).toBeGreaterThan(1);
    await page.goto(`/dashboard/threats/intrusion_sets/${apt28}`);
    await expect(page.getByTestId('curation-possible-duplicate')).toBeVisible();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: `${OUT}/curation-explanation-after-entity-header.png`, clip: { x: 0, y: 0, width: 1440, height: 360 } });
    const query = `query { curationProposalsForEntity(id: "${apt28}") { id proposal_kind proposal_status } }`;
    const proposals = await (await graphqlQuery(request, query)).json();
    const alias = (proposals.data.curationProposalsForEntity as Array<{ id: string; proposal_kind: string; proposal_status: string }>)
      .find((proposal) => proposal.proposal_kind === 'alias' && proposal.proposal_status === 'open');
    expect(alias).toBeDefined();
    await page.goto(`/dashboard/data/curation/inbox/${alias?.id}`);
    await expect(page.getByTestId('curation-proposal-page')).toBeVisible();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: `${OUT}/curation-explanation-after-alias-page.png` });
    await page.getByTestId('curation-proposal-review').click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await page.waitForTimeout(800);
    await dialog.screenshot({ path: `${OUT}/curation-explanation-after-alias-dialog.png` });
  } finally {
    await deleteIntrusionSet(request, fancyBear);
    await deleteIntrusionSet(request, apt28);
  }
});

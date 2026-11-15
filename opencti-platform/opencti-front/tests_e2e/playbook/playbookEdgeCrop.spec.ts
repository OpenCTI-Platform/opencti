import { APIRequestContext, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import { withApiRequest } from '../dataForTesting/graph.data';
import { executeGraphql } from '../dataForTesting/query-utils';

/**
 * Pixel check of the playbook links (#19968, review point B3): every link is drawn on whole pixels,
 * a link between two aligned steps is one straight segment ending on the centre of its card, and two
 * links of one step joining the same step (out + no-match) meet on one end point instead of
 * crossing. Checked at 100% and at a device scale factor of 2, with a crop of each link attached to
 * the report for review.
 *
 *   Listen knowledge events --out--> Match knowledge --out------> Log data in standard output
 *                                                     \--no-match--/
 */
interface CropFixture {
  id: string;
  name: string;
  entryId: string;
  matchId: string;
  loggerId: string;
}

const addNode = async (
  request: APIRequestContext,
  playbookId: string,
  input: { component_id: string; name: string; configuration?: string; parentNodeId?: string; parentPortId?: string },
) => {
  const { playbookAddNode } = await executeGraphql<{ playbookAddNode: string }>(
    request,
    `Add playbook node ${input.name}`,
    'mutation E2EPlaybookCropAddNode($id: ID!, $input: PlaybookAddNodeInput!) { playbookAddNode(id: $id, input: $input) }',
    { id: playbookId, input: { ...input, position: { x: 0, y: 0 } } },
  );
  return playbookAddNode;
};

const createCropFixture = async (request: APIRequestContext): Promise<CropFixture> => {
  const name = `E2E playbook links ${Date.now().toString(36)}`;
  const { playbookAdd } = await executeGraphql<{ playbookAdd: { id: string } }>(
    request,
    `Create playbook ${name}`,
    'mutation E2EPlaybookCropAdd($input: PlaybookAddInput!) { playbookAdd(input: $input) { id } }',
    { input: { name } },
  );
  const { id } = playbookAdd;
  const entryId = await addNode(request, id, {
    component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
    name: 'Listen new reports',
    configuration: JSON.stringify({ create: true, update: false, delete: false }),
  });
  const matchId = await addNode(request, id, {
    component_id: 'PLAYBOOK_FILTERING_COMPONENT',
    name: 'Status is qualified',
    parentNodeId: entryId,
    parentPortId: 'out',
  });
  const loggerId = await addNode(request, id, {
    component_id: 'PLAYBOOK_LOGGER_COMPONENT',
    name: 'Log the bundle',
    configuration: JSON.stringify({ level: 'debug' }),
    parentNodeId: matchId,
    parentPortId: 'out',
  });
  await executeGraphql(
    request,
    `Join the no-match port of ${name}`,
    'mutation E2EPlaybookCropAddLink($id: ID!, $input: PlaybookAddLinkInput!) { playbookAddLink(id: $id, input: $input) }',
    { id, input: { from_node: matchId, from_port: 'no-match', to_node: loggerId } },
  );
  return { id, name, entryId, matchId, loggerId };
};

const deleteCropFixture = async (request: APIRequestContext, fixture: CropFixture | undefined) => {
  if (!fixture) return;
  await executeGraphql(request, `Delete playbook ${fixture.name}`, 'mutation E2EPlaybookCropDelete($id: ID!) { playbookDelete(id: $id) }', { id: fixture.id });
};

/** The numbers of an SVG path, as written in its d attribute. */
const pathNumbers = (d: string) => (d.match(/-?\d+(\.\d+)?/g) ?? []).map(Number);

/** The end point of a path (its last two numbers). */
const pathEnd = (d: string) => {
  const numbers = pathNumbers(d);
  return { x: numbers[numbers.length - 2], y: numbers[numbers.length - 1] };
};

const edgePaths = (page: Page) => page.locator('.react-flow__edge path.react-flow__edge-path');

for (const deviceScaleFactor of [1, 2]) {
  test.describe(`Playbook links at a device scale factor of ${deviceScaleFactor}`, { tag: ['@ee'] }, () => {
    test.use({ deviceScaleFactor, viewport: { width: 1440, height: 900 } });
    test.describe.configure({ mode: 'serial' });
    let fixture: CropFixture;

    test.beforeAll(async ({ playwright }) => {
      fixture = await withApiRequest(playwright, (request) => createCropFixture(request));
    });

    test.afterAll(async ({ playwright }) => {
      await withApiRequest(playwright, (request) => deleteCropFixture(request, fixture));
    });

    const openEditor = async (page: Page) => {
      await page.goto(`/dashboard/data/processing/automation/${fixture.id}`);
      await expect(page.getByTestId(`playbook-node-${fixture.loggerId}`)).toBeVisible();
      await expect(edgePaths(page)).toHaveCount(3);
    };

    test('draws every link on whole pixels, aligned links as one straight segment', async ({ page }, testInfo) => {
      await openEditor(page);
      const paths = await edgePaths(page).all();
      for (const [index, path] of paths.entries()) {
        const d = (await path.getAttribute('d')) ?? '';
        expect(d, `link ${index} has a path`).not.toBe('');
        for (const value of pathNumbers(d)) {
          expect(Number.isInteger(value), `link ${index} coordinate ${value} in "${d}"`).toBe(true);
        }
        await testInfo.attach(`link-${index}@${deviceScaleFactor}x.png`, {
          body: await path.locator('xpath=..').screenshot(),
          contentType: 'image/png',
        });
      }
      // The entry point has one out port and one child laid out under it: one straight segment, no bend.
      const straight = [];
      for (const path of paths) {
        const d = (await path.getAttribute('d')) ?? '';
        if (!d.includes('Q')) straight.push(d);
      }
      expect(straight.length).toBeGreaterThanOrEqual(1);
      for (const d of straight) {
        const numbers = pathNumbers(d);
        expect(numbers).toHaveLength(4);
        // Vertical layout: the same x at both ends.
        expect(numbers[0]).toBe(numbers[2]);
      }
    });

    test('ends the links on the centre of the card they join, the two joining links on one point', async ({ page }) => {
      await openEditor(page);
      const card = page.getByTestId(`playbook-node-${fixture.loggerId}`);
      const cardBox = await card.boundingBox();
      const handleBox = await card.locator('.react-flow__handle.target').boundingBox();
      expect(cardBox).not.toBeNull();
      expect(handleBox).not.toBeNull();
      if (!cardBox || !handleBox) return;
      // The target handle is centred on the card, to the CSS pixel.
      expect(Math.abs((handleBox.x + handleBox.width / 2) - (cardBox.x + cardBox.width / 2))).toBeLessThanOrEqual(0.5);

      const ends = await Promise.all((await edgePaths(page).all()).map(async (path) => pathEnd((await path.getAttribute('d')) ?? '')));
      // The out and no-match links of the match step both end on the logger: one shared end point.
      const counts = new Map<string, number>();
      for (const end of ends) counts.set(`${end.x},${end.y}`, (counts.get(`${end.x},${end.y}`) ?? 0) + 1);
      expect(Math.max(...counts.values())).toBe(2);
    });
  });
}

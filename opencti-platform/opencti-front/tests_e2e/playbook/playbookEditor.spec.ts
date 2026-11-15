import { APIRequestContext, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import { withApiRequest } from '../dataForTesting/graph.data';
import { executeGraphql } from '../dataForTesting/query-utils';
import TextFieldPageModel from '../model/field/TextField.pageModel';

/**
 * The playbook editor canvas (#19968): steps as cards with their port pills, a "+" on every free
 * out port and on every link, the vertical / horizontal layout remembered per playbook, the
 * shortcuts cheat sheet, undo / redo through inverse operations and the node context menu.
 *
 * The playbook is built through the API so every test starts from a known graph:
 *
 *   Listen knowledge events --out--> Match knowledge --out--> Log data in standard output
 *                                         \--no-match--> (free port)
 */
interface PlaybookFixture {
  id: string;
  name: string;
  entryId: string;
  matchId: string;
  loggerId: string;
  matchToLoggerLinkId: string;
}

const addNode = async (
  request: APIRequestContext,
  playbookId: string,
  input: { component_id: string; name: string; configuration?: string; parentNodeId?: string; parentPortId?: string },
) => {
  const { playbookAddNode } = await executeGraphql<{ playbookAddNode: string }>(
    request,
    `Add playbook node ${input.name}`,
    'mutation E2EPlaybookAddNode($id: ID!, $input: PlaybookAddNodeInput!) { playbookAddNode(id: $id, input: $input) }',
    { id: playbookId, input: { ...input, position: { x: 0, y: 0 } } },
  );
  return playbookAddNode;
};

const createPlaybookFixture = async (request: APIRequestContext): Promise<PlaybookFixture> => {
  const name = `E2E playbook editor ${Date.now().toString(36)}`;
  const { playbookAdd } = await executeGraphql<{ playbookAdd: { id: string } }>(
    request,
    `Create playbook ${name}`,
    'mutation E2EPlaybookAdd($input: PlaybookAddInput!) { playbookAdd(input: $input) { id } }',
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
    name: 'Log the qualified bundle',
    configuration: JSON.stringify({ level: 'debug' }),
    parentNodeId: matchId,
    parentPortId: 'out',
  });
  const { playbook } = await executeGraphql<{ playbook: { playbook_definition: string } }>(
    request,
    `Read playbook ${name}`,
    'query E2EPlaybook($id: String!) { playbook(id: $id) { playbook_definition } }',
    { id },
  );
  const definition = JSON.parse(playbook.playbook_definition) as { links: { id: string; from: { id: string }; to: { id: string } }[] };
  const link = definition.links.find((l) => l.from.id === matchId && l.to.id === loggerId);
  if (!link) throw new Error('Fixture playbook: link from the match step to the logger step not found');
  return { id, name, entryId, matchId, loggerId, matchToLoggerLinkId: link.id };
};

const deletePlaybookFixture = async (request: APIRequestContext, fixture: PlaybookFixture | undefined) => {
  if (!fixture) return;
  await executeGraphql(request, `Delete playbook ${fixture.name}`, 'mutation E2EPlaybookDelete($id: ID!) { playbookDelete(id: $id) }', { id: fixture.id });
};

test.describe('Playbook editor', { tag: ['@ee'] }, () => {
  test.describe.configure({ mode: 'serial' });
  let fixture: PlaybookFixture;

  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createPlaybookFixture(request));
  });

  test.afterAll(async ({ playwright }) => {
    await withApiRequest(playwright, (request) => deletePlaybookFixture(request, fixture));
  });

  const steps = (page: Page) => page.locator('.react-flow__node-workflow');
  const step = (page: Page, nodeId: string) => page.getByTestId(`playbook-node-${nodeId}`);
  const freePort = (page: Page, nodeId: string, portId: string) => page.getByTestId(`playbook-add-${nodeId}-${portId}-PLACEHOLDER`);
  const toolbarButton = (page: Page, name: string) => page.getByRole('button', { name, exact: true });
  // The layout switch is a design-system button group: its items are found by their label, whatever their role.
  const layoutItem = (page: Page, name: string) => page.getByLabel(name, { exact: true });

  // The tests run in order on one playbook: each one opens it as the previous one left it.
  const openEditor = async (page: Page) => {
    await page.goto(`/dashboard/data/processing/automation/${fixture.id}`);
    await expect(step(page, fixture.entryId)).toBeVisible();
  };

  /** Picks a component in the palette, names the step and creates it. */
  const createStep = async (page: Page, componentName: string, stepName: string) => {
    await page.getByRole('list', { name: 'Components' }).getByText(componentName, { exact: true }).click();
    const drawer = page.locator('.MuiDrawer-paper');
    await new TextFieldPageModel(page, 'Name', 'text', drawer).fill(stepName);
    await drawer.getByRole('button', { name: 'Create' }).click();
  };

  test('shows every step as a card with its port pills and a "+" on each free out port', async ({ page }) => {
    await openEditor(page);
    await expect(steps(page)).toHaveCount(3);
    await expect(step(page, fixture.entryId)).toContainText('Listen new reports');
    await expect(step(page, fixture.matchId)).toContainText('Status is qualified');
    await expect(step(page, fixture.loggerId)).toContainText('Log the qualified bundle');
    // A step with several out ports names each of them; a single "out" port carries no pill.
    await expect(step(page, fixture.matchId)).toContainText('no-match');
    await expect(freePort(page, fixture.matchId, 'no-match')).toBeVisible();
    await expect(freePort(page, fixture.loggerId, 'out')).toBeVisible();
    // Connected ports carry no "+": the links carry the insertion instead.
    await expect(freePort(page, fixture.matchId, 'out')).toHaveCount(0);
    await expect(page.getByTestId(`playbook-insert-${fixture.matchToLoggerLinkId}`)).toHaveCount(1);
  });

  test('switches between the vertical and horizontal layouts, the choice kept for the playbook', async ({ page }) => {
    await openEditor(page);
    const parent = step(page, fixture.matchId);
    const child = step(page, fixture.loggerId);
    const below = async () => {
      const [p, c] = [await parent.boundingBox(), await child.boundingBox()];
      return Boolean(p && c && c.y > p.y + p.height && Math.abs(c.x - p.x) < p.width);
    };
    const right = async () => {
      const [p, c] = [await parent.boundingBox(), await child.boundingBox()];
      return Boolean(p && c && c.x > p.x + p.width && Math.abs(c.y - p.y) < p.height);
    };
    await expect.poll(below).toBe(true);
    await layoutItem(page, 'Horizontal layout').click();
    await expect.poll(right).toBe(true);
    await page.reload();
    await expect(step(page, fixture.entryId)).toBeVisible();
    await expect.poll(right).toBe(true);
    // The keyboard shortcut switches back.
    await page.locator('.react-flow__pane').click();
    await page.keyboard.press('v');
    await expect.poll(below).toBe(true);
  });

  test('lists the shortcuts in the cheat sheet', async ({ page }) => {
    await openEditor(page);
    await toolbarButton(page, 'Keyboard shortcuts').click();
    const dialog = page.getByRole('dialog', { name: 'Keyboard shortcuts' });
    await expect(dialog).toBeVisible();
    for (const label of ['Zoom in', 'Fit view', 'Vertical layout', 'Undo', 'Redo']) {
      await expect(dialog.getByText(label, { exact: true })).toBeVisible();
    }
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
  });

  test('adds a step on a free port, then undoes and redoes it', async ({ page }) => {
    await openEditor(page);
    await expect(steps(page)).toHaveCount(3);
    await expect(toolbarButton(page, 'Undo')).toBeDisabled();
    await freePort(page, fixture.matchId, 'no-match').getByRole('button', { name: 'Add component' }).click();
    // The palette is searchable (the design-system SearchField is an input of type search: role searchbox).
    await page.getByRole('searchbox', { name: 'Search components' }).fill('log data');
    await createStep(page, 'Log data in standard output', 'Log the rejected bundle');
    await expect(steps(page)).toHaveCount(4);
    await expect(freePort(page, fixture.matchId, 'no-match')).toHaveCount(0);

    await toolbarButton(page, 'Undo').click();
    await expect(steps(page)).toHaveCount(3);
    await expect(freePort(page, fixture.matchId, 'no-match')).toBeVisible();

    await page.locator('.react-flow__pane').click();
    await page.keyboard.press('Shift+ControlOrMeta+z');
    await expect(steps(page)).toHaveCount(4);
    await expect(page.getByText('Log the rejected bundle', { exact: true })).toBeVisible();
  });

  test('inserts a step on a link, between its two steps', async ({ page }) => {
    await openEditor(page);
    await expect(steps(page)).toHaveCount(4);
    const before = 4;
    await page.getByTestId(`playbook-insert-${fixture.matchToLoggerLinkId}`).getByRole('button', { name: 'Insert a component on this link' }).click();
    await createStep(page, 'Reduce knowledge', 'Keep the report only');
    await expect(steps(page)).toHaveCount(before + 1);
    // The new step sits between the match step and the logger step.
    const box = async (nodeId: string) => (await step(page, nodeId).boundingBox())?.y ?? 0;
    const inserted = steps(page).filter({ hasText: 'Keep the report only' });
    await expect.poll(async () => {
      const y = (await inserted.boundingBox())?.y ?? 0;
      return y > await box(fixture.matchId) && y < await box(fixture.loggerId);
    }).toBe(true);
  });

  test('deletes a step from its context menu', async ({ page }) => {
    await openEditor(page);
    await expect(steps(page)).toHaveCount(5);
    const target = steps(page).filter({ hasText: 'Log the rejected bundle' });
    await expect(target).toHaveCount(1);
    const before = 5;
    await target.click({ button: 'right' });
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
    await expect(steps(page)).toHaveCount(before - 1);
    await expect(freePort(page, fixture.matchId, 'no-match')).toBeVisible();
  });
});

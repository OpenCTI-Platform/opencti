import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, createInvestigation, deleteGraphFixture, deleteInvestigation, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';

/**
 * The capabilities the elevated graph adds on every surface: legend counters as filters,
 * group-by-type collapse, hover card and its quick actions, deterministic layouts, shortest path,
 * neighbourhood selection, navigation controls, full screen, keyboard shortcuts, high-resolution
 * export and the accessible list of the graph elements.
 */
test.describe('Graph experience', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });
  let fixture: GraphFixture;

  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createGraphFixture(request));
  });

  test.afterAll(async ({ playwright }) => {
    await withApiRequest(playwright, (request) => deleteGraphFixture(request, fixture));
  });

  const openGraph = async (page: Page) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/graph`);
    await graph.waitForGraph(5);
    return graph;
  };
  const legend = (page: Page) => page.getByRole('region', { name: 'Legend' });
  const elements = (page: Page) => page.getByRole('listbox', { name: 'Elements of the graph' });

  test('counts the entity types in the legend, each counter filtering its type', async ({ page }) => {
    const graph = await openGraph(page);
    await expect(legend(page)).toBeVisible();
    const malwareCounter = legend(page).getByRole('button', { name: 'Malware: 1' });
    await expect(malwareCounter).toHaveAttribute('aria-pressed', 'true');
    await malwareCounter.click();
    await expect.poll(async () => (await graph.snapshot()).nodes.filter((n) => n.disabled).map((n) => n.id)).toEqual([fixture.malware.id]);
    await expect(malwareCounter).toHaveAttribute('aria-pressed', 'false');
    await malwareCounter.click();
    await expect.poll(async () => (await graph.snapshot()).nodes.filter((n) => n.disabled)).toHaveLength(0);

    // Relationship types filter their links only.
    await legend(page).getByRole('button', { name: /communicates with: 1/i }).click();
    await expect.poll(async () => (await graph.snapshot()).links.filter((l) => l.disabled).length).toBe(1);
    await graph.getToolbarButton('Clear all filters').click();
    await expect.poll(async () => (await graph.snapshot()).links.filter((l) => l.disabled).length).toBe(0);

    // The legend can be hidden and the choice is kept.
    await graph.getControl('Hide the legend').click();
    await expect(legend(page)).toBeHidden();
    await page.reload();
    await graph.waitForGraph(5);
    await expect(legend(page)).toBeHidden();
    await graph.getControl('Show the legend').click();
    await expect(legend(page)).toBeVisible();
  });

  test('collapses a type into one group node and expands it back', async ({ page }) => {
    await openGraph(page);
    await legend(page).getByRole('button', { name: 'Collapse into one node' }).first().click();
    await expect(elements(page).getByRole('option', { name: /1 \u00d7 / })).toHaveCount(1);
    await legend(page).getByRole('button', { name: 'Expand the group' }).click();
    await expect(elements(page).getByRole('option', { name: /\u00d7/ })).toHaveCount(0);
    await expect(elements(page).getByRole('option')).toHaveCount(9);
  });

  test('opens a hover card with the facts and quick actions of a node', async ({ page }) => {
    const graph = await openGraph(page);
    await graph.arrangeInMiddle([fixture.intrusionSet.id]);
    await graph.waitForGraph(5);
    await graph.hoverNode(fixture.intrusionSet.id);
    const card = page.getByRole('group', { name: 'Details on hover' });
    await expect(card).toBeVisible();
    await expect(card.getByText(fixture.intrusionSet.name)).toBeVisible();
    await expect(card.getByText('TLP:GREEN').first()).toBeVisible();
    await expect(card.getByText(fixture.authorName)).toBeVisible();

    await card.getByRole('button', { name: 'Hide from the view' }).click();
    await expect(elements(page).getByRole('option', { name: new RegExp(fixture.intrusionSet.name) })).toHaveCount(0);
    await legend(page).getByRole('button', { name: /Show the hidden entities/ }).click();
    // The entity option ends with its relationship count; the options of its relationships also name it.
    await expect(elements(page).getByRole('option', { name: new RegExp(`${fixture.intrusionSet.name}, \\d+ relationships?$`) })).toHaveCount(1);
  });

  test('starts an investigation from the hover card of an entity', async ({ page, playwright }) => {
    const graph = await openGraph(page);
    await graph.arrangeInMiddle([fixture.malware.id]);
    await graph.waitForGraph(5);
    await graph.hoverNode(fixture.malware.id);
    const card = page.getByRole('group', { name: 'Details on hover' });
    await card.getByRole('button', { name: 'Start an investigation' }).click();
    await page.waitForURL(/\/dashboard\/workspaces\/investigations\/[0-9a-f-]{36}$/);
    const investigationId = new URL(page.url()).pathname.split('/').pop() ?? '';
    try {
      await graph.waitForGraph(1);
      expect((await graph.snapshot()).nodes.map((n) => n.id)).toContain(fixture.malware.id);
    } finally {
      await withApiRequest(playwright, (request) => deleteInvestigation(request, investigationId));
    }
  });

  test('arranges the graph by entity tier and around a selected entity', async ({ page }) => {
    const graph = await openGraph(page);
    await graph.getToolbarButton('Enable the layout by entity tier').click();
    await expect(graph.getToolbarButton('Disable the layout by entity tier')).toBeVisible();
    await graph.waitForGraph(5);
    const tiers = await graph.snapshot();
    const gx = (id: string) => tiers.nodes.find((n) => n.id === id)?.gx ?? NaN;
    expect(gx(fixture.intrusionSet.id)).toBeLessThan(gx(fixture.malware.id));
    expect(gx(fixture.malware.id)).toBeLessThan(gx(fixture.attackPattern.id));
    expect(gx(fixture.attackPattern.id)).toBeLessThan(gx(fixture.ipv4.id));
    await graph.getToolbarButton('Disable the layout by entity tier').click();

    await graph.arrangeInMiddle([fixture.malware.id]);
    await graph.waitForGraph(5);
    await graph.clickNode(fixture.malware.id);
    await graph.getToolbarButton('Enable the radial layout around the selection').click();
    await graph.waitForGraph(5);
    const radial = await graph.snapshot();
    const centre = radial.nodes.find((n) => n.id === fixture.malware.id);
    expect(Math.hypot(centre?.gx ?? NaN, centre?.gy ?? NaN)).toBeLessThan(1);
    await graph.getToolbarButton('Disable the radial layout').click();
  });

  test('highlights the shortest path between two nodes and selects neighbourhoods', async ({ page }) => {
    const graph = await openGraph(page);
    const list = elements(page);
    await list.focus();
    // The first option is selected with Enter, a later one added with Shift+Enter.
    await list.press('Home');
    await list.press('Enter');
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.clickBackground();

    await graph.arrangeInMiddle([fixture.intrusionSet.id, fixture.ipv4.id]);
    await graph.waitForGraph(5);
    await graph.clickNode(fixture.intrusionSet.id);
    await graph.clickNode(fixture.ipv4.id, ['Shift']);
    await expect(graph.getSelectionSummary(2)).toBeVisible();
    await graph.getToolbarButton('Highlight the shortest path between the two selected nodes').click();
    await expect(graph.getToolbarButton('Clear the highlighted path')).toBeVisible();
    await graph.getToolbarButton('Clear the highlighted path').click();

    await graph.clickBackground();
    await graph.clickNode(fixture.attackPattern.id);
    await graph.getToolbarButton('Select the neighbours of the selected nodes').click();
    await expect(graph.getSelectionSummary(3)).toBeVisible();
  });

  test('navigates with the controls, the keyboard and full screen', async ({ page }) => {
    const graph = await openGraph(page);
    const before = (await graph.snapshot()).zoom;
    await graph.getControl('Zoom in').click();
    await expect.poll(async () => (await graph.snapshot()).zoom).toBeGreaterThan(before);
    await graph.getControl('Fit the whole graph').click();

    await graph.getCanvas().hover({ position: { x: 300, y: 20 } });
    await page.keyboard.press('?');
    const shortcuts = page.getByRole('dialog').filter({ hasText: 'Keyboard shortcuts' });
    await expect(shortcuts).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(shortcuts).toBeHidden();
    await graph.getCanvas().hover({ position: { x: 300, y: 20 } });
    await page.keyboard.press('g');
    await expect(legend(page)).toBeHidden();
    await page.keyboard.press('g');
    await expect(legend(page)).toBeVisible();

    await graph.getControl('Show the graph full screen').click();
    await expect(graph.getControl('Leave full screen')).toBeVisible();
    await graph.waitForGraph(5);
    await graph.getControl('Leave full screen').click();
    await expect(graph.getControl('Show the graph full screen')).toBeVisible();
  });

  test('exports the whole graph as a high-resolution image with its legend', async ({ page }) => {
    const graph = await openGraph(page);
    const download = page.waitForEvent('download');
    await graph.getControl('Export the whole graph as a high-resolution image').click();
    expect((await download).suggestedFilename()).toMatch(/\.png$/);
  });

  test('says why nothing is drawn and offers the next action', async ({ page, playwright }) => {
    // Every entity type faded in the legend: the filters leave nothing, and clearing them restores the graph.
    const graph = await openGraph(page);
    const typeCounters = legend(page).getByRole('button', { name: /^(Intrusion set|Malware|Attack pattern|IPv4 address|Domain name): 1$/i });
    await expect(typeCounters).toHaveCount(5);
    for (const counter of await typeCounters.all()) await counter.click();
    const filtered = page.getByRole('status').filter({ hasText: 'No entity matches these filters' });
    await expect(filtered).toBeVisible();
    await filtered.getByRole('button', { name: 'Clear filters' }).click();
    await expect(filtered).toBeHidden();
    await expect.poll(async () => (await graph.snapshot()).nodes.filter((n) => n.disabled)).toHaveLength(0);

    // An investigation without any entity yet says how to start one.
    const investigationId = await withApiRequest(playwright, (request) => createInvestigation(request, `Graph empty investigation ${fixture.suffix}`, []));
    try {
      await page.goto(`/dashboard/workspaces/investigations/${investigationId}`);
      await expect(page.getByRole('status').filter({ hasText: 'Nothing to draw yet' })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Read the documentation' })).toBeVisible();
    } finally {
      await withApiRequest(playwright, (request) => deleteInvestigation(request, investigationId));
    }
  });
});

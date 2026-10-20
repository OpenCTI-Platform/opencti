import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createLargeGraphFixture, deleteLargeGraphFixture, LargeGraphFixture, withApiRequest } from '../dataForTesting/graph.data';

/** 20 malware and 480 domain names: 500 nodes; 960 communications and 40 variants: 1,000 links. */
const SHAPE = { hubs: 20, spokes: 24, hubsPerSpoke: 2, variantsPerHub: 2 };
const NODES = SHAPE.hubs * (SHAPE.spokes + 1);
const LINKS = SHAPE.hubs * SHAPE.spokes * SHAPE.hubsPerSpoke + SHAPE.hubs * SHAPE.variantsPerHub;
const SAMPLE_MS = 3000;

/** Intervals between the animation frames of the page, in milliseconds, over `durationMs`. */
const sampleFrameIntervals = (durationMs: number) => new Promise<number[]>((resolve) => {
  const intervals: number[] = [];
  let last = performance.now();
  const end = last + durationMs;
  const tick = (now: number) => {
    intervals.push(now - last);
    last = now;
    if (now < end) requestAnimationFrame(tick);
    else resolve(intervals);
  };
  requestAnimationFrame(tick);
});

const percentile = (values: number[], p: number) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
};

/**
 * The drawing of a large investigation, 500 nodes and 1,000 links: the time until its first layout
 * stands still, then the frame rate while the forces lay it out again, when every frame moves and
 * repaints every node and link (the heaviest steady work the graph does). The budgets are loose on
 * purpose (CI browsers render without a GPU); they catch a drawing that stops scaling. The measures
 * are printed and attached to the report.
 */
test.describe('Graph performance', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial', timeout: 600000 });
  let fixture: LargeGraphFixture;

  test.beforeAll(async ({ playwright }) => {
    test.setTimeout(600000);
    fixture = await withApiRequest(playwright, (request) => createLargeGraphFixture(request, SHAPE));
  });

  test.afterAll(async ({ playwright }) => {
    test.setTimeout(600000);
    await withApiRequest(playwright, (request) => deleteLargeGraphFixture(request, fixture));
  });

  test('lays out a large investigation and keeps it smooth while the forces run', async ({ page }) => {
    const graph = new GraphPage(page);
    const start = Date.now();
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigationId}`);
    const stableAfterMs = await graph.waitForStableLayout(NODES, LINKS);
    const snapshot = await graph.snapshot();
    expect(snapshot.nodes.length).toBe(NODES);
    expect(snapshot.links.length).toBeGreaterThanOrEqual(LINKS);
    const layoutMs = stableAfterMs - start;

    await graph.runToolbarAction('Unfix the nodes and re-apply forces');
    const intervals = await page.evaluate(sampleFrameIntervals, SAMPLE_MS);
    const median = percentile(intervals, 50);
    const p90 = percentile(intervals, 90);
    const measures = `${snapshot.nodes.length} nodes, ${snapshot.links.length} links: loaded and laid out in ${(layoutMs / 1000).toFixed(1)} s after navigation; `
      + `frame time while the forces run median ${median.toFixed(1)} ms, p90 ${p90.toFixed(1)} ms over ${intervals.length} frames`;
    test.info().annotations.push({ type: 'graph performance', description: measures });
    console.log(`Graph performance - ${measures}`);
    expect(layoutMs).toBeLessThan(60000);
    expect(median).toBeLessThan(50);
    expect(p90).toBeLessThan(120);
  });
});

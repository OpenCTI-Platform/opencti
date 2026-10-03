import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createLargeGraphFixture, deleteLargeGraphFixture, LargeGraphFixture, withApiRequest } from '../dataForTesting/graph.data';

const HUBS = 10;
const SPOKES = 30;
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
 * The frame rate of a large investigation while the forces lay it out again: every frame then
 * moves and repaints every node and link, the heaviest steady work the graph does. The budget is
 * loose on purpose (CI browsers render without a GPU); it catches a drawing that stops scaling.
 */
test.describe('Graph performance', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial', timeout: 300000 });
  let fixture: LargeGraphFixture;

  test.beforeAll(async ({ playwright }) => {
    test.setTimeout(300000);
    fixture = await withApiRequest(playwright, (request) => createLargeGraphFixture(request, HUBS, SPOKES));
  });

  test.afterAll(async ({ playwright }) => {
    test.setTimeout(300000);
    await withApiRequest(playwright, (request) => deleteLargeGraphFixture(request, fixture));
  });

  test('keeps a large investigation smooth while the forces lay it out', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigationId}`);
    const nodeCount = HUBS * (SPOKES + 1);
    await graph.waitForGraph(nodeCount);
    expect((await graph.snapshot()).links.length).toBeGreaterThanOrEqual(HUBS * SPOKES);

    await graph.getToolbarButton('Unfix the nodes and re-apply forces').click();
    const intervals = await page.evaluate(sampleFrameIntervals, SAMPLE_MS);
    const median = percentile(intervals, 50);
    const p90 = percentile(intervals, 90);
    test.info().annotations.push({ type: 'frame intervals', description: `median ${median.toFixed(1)} ms, p90 ${p90.toFixed(1)} ms, ${intervals.length} frames` });
    expect(median).toBeLessThan(50);
    expect(p90).toBeLessThan(120);
  });
});

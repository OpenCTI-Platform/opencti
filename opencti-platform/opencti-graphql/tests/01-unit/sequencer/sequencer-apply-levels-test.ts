import { describe, expect, it } from 'vitest';
import { computeApplyLevels, groupIndicesByLevel, runBounded } from '../../../src/database/sequencer/sequencer-apply-levels';
import { getCurrentStripSink, withStripSink } from '../../../src/database/sequencer/sequencer-strip-sink';

describe('sequencer apply levels', () => {
  it('gives level 0 to groups without in-batch producers and one more than the deepest producer otherwise', () => {
    const order = [{}, { dependsOn: [0] }, { dependsOn: [0] }, { dependsOn: [1, 2] }, {}];
    expect(computeApplyLevels(order)).toEqual([0, 1, 1, 2, 0]);
  });

  it('ignores forward or invalid producer positions', () => {
    expect(computeApplyLevels([{ dependsOn: [3] }, { dependsOn: [-1] }, { dependsOn: [1] }])).toEqual([0, 0, 1]);
  });

  it('groups indices by contiguous level, in plan order inside a level', () => {
    expect(groupIndicesByLevel([0, 1, 1, 2, 0])).toEqual([[0, 4], [1, 2], [3]]);
    expect(groupIndicesByLevel([])).toEqual([]);
  });

  it('runBounded never exceeds the limit, overlaps tasks, and keeps result order', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const results = await runBounded(items, 4, async (i) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => {
        setTimeout(r, (20 - i) % 5);
      });
      inFlight -= 1;
      return i * 2;
    });
    expect(maxInFlight).toBeLessThanOrEqual(4);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(results).toEqual(items.map((i) => i * 2));
  });

  it('runBounded with limit 1 is sequential and ordered', async () => {
    const seen: number[] = [];
    await runBounded([3, 1, 2], 1, async (i) => {
      await Promise.resolve();
      seen.push(i);
    });
    expect(seen).toEqual([3, 1, 2]);
  });
});

describe('strip sink per apply', () => {
  it('lets concurrent applies each see their own sink across awaits', async () => {
    const a: { targetRef: string; relType: string }[] = [];
    const b: { targetRef: string; relType: string }[] = [];
    const apply = (sink: { targetRef: string; relType: string }[], tag: string) => withStripSink(sink, async () => {
      await new Promise((r) => {
        setTimeout(r, 5);
      });
      getCurrentStripSink()?.push({ targetRef: tag, relType: 'r' });
      await new Promise((r) => {
        setTimeout(r, 1);
      });
      getCurrentStripSink()?.push({ targetRef: `${tag}2`, relType: 'r' });
    });
    await Promise.all([apply(a, 'a'), apply(b, 'b')]);
    expect(a.map((s) => s.targetRef)).toEqual(['a', 'a2']);
    expect(b.map((s) => s.targetRef)).toEqual(['b', 'b2']);
    expect(getCurrentStripSink()).toBeNull();
  });
});

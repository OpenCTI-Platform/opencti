import { describe, it, expect } from 'vitest';
import { buildGraph, rankGraph } from './rank';
import { buildElements, SAMPLES, transitionId } from './layoutFixtures';

const rankSample = (key: keyof typeof SAMPLES) => {
  const { nodes, edges } = buildElements(SAMPLES[key]);
  return rankGraph(buildGraph(nodes, edges));
};

describe('rankGraph – cycle breaking', () => {
  it('marks reject and reopen as backward in Report review', () => {
    const ranked = rankSample('review');
    expect([...ranked.backwardTransitions].sort()).toEqual([
      transitionId(['ANALYZED'], 'reopen', 'IN_REVIEW'),
      transitionId(['IN_REVIEW'], 'reject', 'NEW'),
    ].sort());
  });

  it('marks only reopen as backward in Incident response', () => {
    expect([...rankSample('incident').backwardTransitions]).toEqual([transitionId(['RESOLVED'], 'reopen', 'TRIAGED')]);
  });

  it('marks a self-loop as backward', () => {
    expect(rankSample('rfi').backwardTransitions.has(transitionId(['IN_PROGRESS'], 'add_note', 'IN_PROGRESS'))).toBe(true);
  });

  it('starts from the first status in model order when every status has an incoming edge', () => {
    const ranked = rankGraph(buildGraph(
      [{ id: 'A', type: 'status' }, { id: 'B', type: 'status' }, { id: 't1', type: 'transition' }, { id: 't2', type: 'transition' }],
      [{ id: 'a1', source: 'A', target: 't1' }, { id: 'a2', source: 't1', target: 'B' }, { id: 'b1', source: 'B', target: 't2' }, { id: 'b2', source: 't2', target: 'A' }],
    ));
    expect([...ranked.backwardTransitions]).toEqual(['t2']);
    expect(ranked.rank.get('A')).toBe(0);
  });
});

describe('rankGraph – ranks', () => {
  it('puts statuses on even rows and transitions and placeholders on odd rows', () => {
    const { nodes, edges } = buildElements(SAMPLES.case);
    const ranked = rankGraph(buildGraph(nodes, edges));
    ranked.rank.forEach((r, id) => {
      const type = nodes.find((n) => n.id === id)!.type;
      expect(r % 2 === 0).toBe(type === 'status');
    });
  });

  it('places a merge status below all of its parents', () => {
    const ranked = rankSample('incident');
    const containment = ranked.rank.get('CONTAINMENT')!;
    expect(containment).toBeGreaterThan(ranked.rank.get(transitionId(['TRIAGED'], 'contain', 'CONTAINMENT'))!);
    expect(containment).toBeGreaterThan(ranked.rank.get(transitionId(['ESCALATED'], 'contain', 'CONTAINMENT'))!);
  });

  it('places a multi-source transition one row below its lowest source', () => {
    const ranked = rankSample('rfi');
    const cancel = transitionId(['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED'], 'cancel', 'CANCELLED');
    const lowest = Math.max(...['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED'].map((s) => ranked.rank.get(s)!));
    expect(ranked.rank.get(cancel)).toBe(lowest + 1);
  });

  it('adds one dummy per crossed row on long edges', () => {
    const ranked = rankSample('incident');
    const edgeId = `e-${transitionId(['TRIAGED'], 'false_positive', 'CLOSED')}->CLOSED`;
    const chain = ranked.chains.get(edgeId)!;
    const span = ranked.rank.get('CLOSED')! - ranked.rank.get(transitionId(['TRIAGED'], 'false_positive', 'CLOSED'))!;
    expect(chain.length).toBe(span + 1);
    expect(chain.slice(1, -1).every((id) => ranked.layered.get(id)!.dummy)).toBe(true);
  });

  it('ignores edges whose endpoints are missing', () => {
    const graph = buildGraph([{ id: 'A', type: 'status' }], [{ id: 'ghost', source: 'A', target: 'nowhere' }]);
    expect(graph.edges).toEqual([]);
  });
});

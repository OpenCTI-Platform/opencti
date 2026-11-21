import { describe, expect, it } from 'vitest';
import { buildProofGraph, type ProofGraphMatch, type ProofGraphOptions, sharedEntities } from './irProofGraph';

const ALL: ProofGraphOptions = { minScore: 0, types: [], criteria: [], includeProposed: true, limit: 100 };

const graphProof = (criterion: string, anchor: string, rel: string, direction = 'outgoing') => ({
  criterion_id: criterion, kind: 'graph', anchor_id: anchor, anchor_type: 'Intrusion-Set', anchor: { representative: { main: anchor.toUpperCase() } }, relationship_type: rel, direction,
});

const match = (id: string, type: string, score: number, explanations: ProofGraphMatch['match_explanations'], status = 'auto'): ProofGraphMatch => ({
  id: `m-${id}`,
  match_status: status,
  match_score: score,
  match_excluded: false,
  match_entity_type: type,
  match_entity_id: id,
  match_criteria_ids: Array.from(new Set(explanations.map((e) => e.criterion_id))),
  entity: { representative: { main: id } },
  match_explanations: explanations,
});

const MATCHES = [
  // A malware used by two DPRK sets, and a vulnerability it exploits (second hop)
  match('appleseed', 'Malware', 80, [graphProof('c-arsenal', 'kimsuky', 'uses'), graphProof('c-arsenal', 'lazarus', 'uses')]),
  match('cve-1', 'Vulnerability', 60, [graphProof('c-vulns', 'appleseed', 'exploits')]),
  // An actor that targets the finance sector: the entity is the source of the relationship
  match('apt45', 'Intrusion-Set', 40, [graphProof('c-actors', 'finance', 'targets', 'incoming')], 'proposed'),
  match('report-x', 'Report', 30, [{ criterion_id: 'c-kw', kind: 'keywords', keyword: 'Lazarus' }]),
  match('ip-1', 'IPv4-Addr', 20, [{ criterion_id: 'c-kw', kind: 'keywords', keyword: 'lazarus', container_id: 'report-y', container_type: 'Report', container: { representative: { main: 'Report Y' } } }]),
];

describe('proof graph of a requirement', () => {
  it('draws the entities, their starting points and the relationships that brought them in', () => {
    const graph = buildProofGraph(MATCHES, ALL);
    const ids = graph.nodes.map((n) => `${n.kind}:${n.id}`);
    expect(ids).toEqual(expect.arrayContaining(['entity:appleseed', 'anchor:kimsuky', 'anchor:lazarus', 'entity:cve-1', 'anchor:finance', 'keyword:keyword:lazarus', 'container:report-y']));
    expect(graph.links.map((l) => l.id)).toEqual(expect.arrayContaining([
      'kimsuky|uses|appleseed',
      'appleseed|exploits|cve-1', // the second hop reuses the entity node
      'apt45|targets|finance', // incoming: the entity is the source
      'keyword:lazarus|mentions|report-x',
      'report-y|object|ip-1',
    ]));
    expect(graph.nodes.filter((n) => n.id === 'appleseed')).toHaveLength(1);
    expect(graph.nodes.filter((n) => n.id === 'keyword:lazarus')).toHaveLength(1); // one node per keyword, whatever its case
  });

  it('filters on score, type, criterion and status, and keeps the best scores within the limit', () => {
    expect(buildProofGraph(MATCHES, { ...ALL, minScore: 50 }).nodes.filter((n) => n.kind === 'entity').map((n) => n.id)).toEqual(['appleseed', 'cve-1']);
    expect(buildProofGraph(MATCHES, { ...ALL, types: ['Vulnerability'] }).nodes.map((n) => n.id)).toEqual(['cve-1', 'appleseed']);
    expect(buildProofGraph(MATCHES, { ...ALL, includeProposed: false }).nodes.some((n) => n.id === 'apt45')).toBe(false);
    const limited = buildProofGraph(MATCHES, { ...ALL, limit: 1 });
    expect(limited.total).toBe(5);
    expect(limited.nodes.map((n) => n.id)).toEqual(['appleseed', 'kimsuky', 'lazarus']);
    const byCriterion = buildProofGraph(MATCHES, { ...ALL, criteria: ['c-vulns'] });
    expect(byCriterion.nodes.map((n) => `${n.kind}:${n.id}`)).toEqual(['entity:cve-1', 'anchor:appleseed']);
  });

  it('ranks the entities shared by several starting points', () => {
    const shared = sharedEntities(buildProofGraph(MATCHES, ALL));
    expect(shared.map((n) => [n.id, n.sources])).toEqual([['appleseed', 2]]);
  });
});

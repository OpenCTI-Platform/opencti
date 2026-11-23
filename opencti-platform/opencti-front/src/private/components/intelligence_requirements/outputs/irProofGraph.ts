// Graph view of a requirement: the entities of the requirement and the proofs that brought them in.
// Not the knowledge graph: only the relationships (or containers, keywords) that explain why each entity entered.

export interface ProofGraphExplanation {
  readonly criterion_id: string;
  readonly kind: string;
  readonly anchor_id?: string | null;
  readonly anchor_type?: string | null;
  readonly anchor?: { readonly representative: { readonly main: string } } | null;
  readonly relationship_type?: string | null;
  readonly direction?: string | null;
  readonly keyword?: string | null;
  readonly container_id?: string | null;
  readonly container_type?: string | null;
  readonly container?: { readonly representative: { readonly main: string } } | null;
}

export interface ProofGraphMatch {
  readonly id: string;
  readonly match_status: string;
  readonly match_score: number;
  readonly match_excluded: boolean;
  readonly match_entity_type: string;
  readonly match_entity_id: string;
  readonly match_criteria_ids: readonly string[];
  readonly entity?: { readonly representative: { readonly main: string } } | null;
  readonly match_explanations: readonly ProofGraphExplanation[];
}

export interface ProofGraphOptions {
  minScore: number;
  types: string[]; // empty = every type
  criteria: string[]; // empty = every criterion
  includeProposed: boolean;
  limit: number; // entities of the requirement, best scores first
}

// entity: in the requirement · anchor: a starting point of a proof (subject, or an entity of the requirement not shown)
// container: a container that mentions a keyword · keyword: a keyword found in the text of the entity itself
export type ProofNodeKind = 'entity' | 'anchor' | 'container' | 'keyword';

export interface ProofGraphNode {
  id: string;
  entity_type: string;
  name: string;
  kind: ProofNodeKind;
  score: number | null;
  status: string | null;
  matchId: string | null;
  sources: number; // distinct starting points that bring the entity in
}

export interface ProofGraphLink {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  criterion_ids: string[];
}

export interface ProofGraph {
  nodes: ProofGraphNode[];
  links: ProofGraphLink[];
  total: number; // entities that pass the filters, before the limit
}

export const IN_REQUIREMENT_STATUSES = ['auto', 'accepted'];
export const KEYWORD_RELATIONSHIP = 'mentions';

export const buildProofGraph = (matches: readonly ProofGraphMatch[], options: ProofGraphOptions): ProofGraph => {
  const statuses = options.includeProposed ? [...IN_REQUIREMENT_STATUSES, 'proposed'] : IN_REQUIREMENT_STATUSES;
  const kept = matches
    .filter((m) => statuses.includes(m.match_status) && !m.match_excluded)
    .filter((m) => m.match_score >= options.minScore)
    .filter((m) => options.types.length === 0 || options.types.includes(m.match_entity_type))
    .filter((m) => options.criteria.length === 0 || m.match_criteria_ids.some((c) => options.criteria.includes(c)))
    .sort((a, b) => b.match_score - a.match_score);
  const shown = kept.slice(0, options.limit);

  const nodes = new Map<string, ProofGraphNode>();
  const links = new Map<string, ProofGraphLink>();
  // The entities first: an anchor that is itself shown (second hop) is drawn once, as an entity
  shown.forEach((m) => nodes.set(m.match_entity_id, {
    id: m.match_entity_id,
    entity_type: m.match_entity_type,
    name: m.entity?.representative.main ?? m.match_entity_id,
    kind: 'entity',
    score: m.match_score,
    status: m.match_status,
    matchId: m.id,
    sources: 0,
  }));
  const addNode = (id: string, entityType: string, name: string, kind: ProofNodeKind) => {
    if (!nodes.has(id)) nodes.set(id, { id, entity_type: entityType, name, kind, score: null, status: null, matchId: null, sources: 0 });
  };
  const addLink = (source: string, target: string, relationshipType: string, criterionId: string) => {
    const id = `${source}|${relationshipType}|${target}`;
    const existing = links.get(id);
    if (existing) {
      if (!existing.criterion_ids.includes(criterionId)) existing.criterion_ids.push(criterionId);
    } else {
      links.set(id, { id, source, target, relationship_type: relationshipType, criterion_ids: [criterionId] });
    }
  };

  shown.forEach((m) => {
    const entityId = m.match_entity_id;
    const origins = new Set<string>();
    m.match_explanations
      .filter((e) => options.criteria.length === 0 || options.criteria.includes(e.criterion_id))
      .forEach((e) => {
        if (e.kind === 'graph' && e.anchor_id && e.anchor_id !== entityId) {
          addNode(e.anchor_id, e.anchor_type ?? 'Unknown', e.anchor?.representative.main ?? e.anchor_id, 'anchor');
          const rel = e.relationship_type ?? 'related-to';
          // incoming: the entity is the source of the relationship towards the starting point
          if (e.direction === 'incoming') addLink(entityId, e.anchor_id, rel, e.criterion_id);
          else addLink(e.anchor_id, entityId, rel, e.criterion_id);
          origins.add(e.anchor_id);
        } else if (e.kind === 'keywords' && e.container_id) {
          addNode(e.container_id, e.container_type ?? 'Report', e.container?.representative.main ?? e.container_id, 'container');
          addLink(e.container_id, entityId, 'object', e.criterion_id);
          origins.add(e.container_id);
        } else if (e.kind === 'keywords' && e.keyword) {
          const keywordId = `keyword:${e.keyword.toLowerCase()}`;
          addNode(keywordId, 'Label', `#${e.keyword}`, 'keyword');
          addLink(keywordId, entityId, KEYWORD_RELATIONSHIP, e.criterion_id);
          origins.add(keywordId);
        }
      });
    const node = nodes.get(entityId);
    if (node) node.sources = origins.size;
  });

  return { nodes: Array.from(nodes.values()), links: Array.from(links.values()), total: kept.length };
};

// Entities brought in by several starting points, the most shared first (the prevalence, seen in the graph)
export const sharedEntities = (graph: ProofGraph, min = 2) => graph.nodes
  .filter((n) => n.kind === 'entity' && n.sources >= min)
  .sort((a, b) => b.sources - a.sources || (b.score ?? 0) - (a.score ?? 0));

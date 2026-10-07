import {
  ACTION_ACKNOWLEDGE,
  ACTION_ADD_ALIASES,
  ACTION_FIX_DATES,
  ACTION_MERGE,
  ACTION_PRESERVE_PROCEDURE,
  ACTION_RESOLVE_ATTRIBUTION,
  ACTION_REVOKE,
  ACTION_UNMERGE,
  ACTION_UNREVOKE_INDICATOR,
  type CurationCandidateEntity,
  type CurationEvidence,
  DETECTOR_BEHAVIOR,
  DETECTOR_COMBINED,
  DETECTOR_CONTRADICTION,
  DETECTOR_NORMALIZATION,
  DETECTOR_RELATIONSHIP_CONFLICT,
  DETECTOR_SIMILARITY,
  DETECTOR_STALENESS,
  type CurationSettings,
  EVIDENCE_ATTACK_OVERLAP,
  EVIDENCE_ATTRIBUTION_CONFLICT,
  EVIDENCE_CANONICAL_COLLISION,
  EVIDENCE_CO_ATTRIBUTION,
  EVIDENCE_DATE_INVERSION,
  EVIDENCE_DECAYED_INDICATOR,
  EVIDENCE_DESCRIPTION_SIMILARITY,
  EVIDENCE_GRAPH_SIMILARITY,
  EVIDENCE_MERGED_ENTITY,
  EVIDENCE_PROCEDURE_CONFLICT,
  EVIDENCE_REVOKED_INDICATOR,
  EVIDENCE_SHARED_ALIAS,
  EVIDENCE_SHARED_INFRASTRUCTURE,
  EVIDENCE_SHARED_TOOLS,
  EVIDENCE_SOURCE_AGREEMENT,
  EVIDENCE_STALENESS,
  EVIDENCE_TAXONOMY,
  EVIDENCE_TRIGRAM,
  EVIDENCE_TYPE_COLLISION,
  EVIDENCE_VICTIMOLOGY,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
  PROPOSAL_KIND_SPLIT,
  PROPOSAL_KIND_STALE,
  PROPOSAL_KIND_TYPE_MISMATCH,
  type ProposalDraft,
} from './curation-types';
import {
  bestTrigramMatch,
  buildTfIdfVectors,
  canonicalizeEntityNames,
  type CanonicalForms,
  combineEvidence,
  comparableName,
  getTaxonomyFamily,
  intersection,
  jaccard,
  roundScore,
  sparseCosine,
  type TaxonomyFamily,
  topSharedTerms,
  trigrams,
} from './curation-normalization';
import { findSharedTaxonomyCluster, findTaxonomyClusters, getTaxonomySourceReliability, suggestTaxonomyAliases } from './curation-taxonomy';

// region model
export interface CuratedEntity extends CurationCandidateEntity {
  names: string[];
  canonicals: CanonicalForms;
}

export const toCuratedEntity = (candidate: CurationCandidateEntity): CuratedEntity => {
  const names = [candidate.name, ...candidate.aliases].filter((value): value is string => typeof value === 'string' && value.trim().length > 0);
  return { ...candidate, names, canonicals: canonicalizeEntityNames(names, candidate.entity_type) };
};

export interface NeighborSets {
  techniques: Set<string>;
  tools: Set<string>;
  infrastructure: Set<string>;
  victims: Set<string>;
  campaigns: Set<string>;
}

export const emptyNeighborSets = (): NeighborSets => ({
  techniques: new Set(),
  tools: new Set(),
  infrastructure: new Set(),
  victims: new Set(),
  campaigns: new Set(),
});

export interface PairSignals {
  left: CuratedEntity;
  right: CuratedEntity;
  evidence: CurationEvidence[];
  detectors: Set<string>;
}

export const pairKey = (leftId: string, rightId: string) => (leftId < rightId ? `${leftId}|${rightId}` : `${rightId}|${leftId}`);

const appendTo = <K, V>(map: Map<K, V[]>, key: K, value: V) => {
  const bucket = map.get(key);
  if (bucket) {
    bucket.push(value);
  } else {
    map.set(key, [value]);
  }
};

const evidence = (evidenceType: string, score: number, weight: number, description: string, details?: Record<string, unknown>): CurationEvidence => ({
  evidence_type: evidenceType,
  score: roundScore(score),
  weight,
  description,
  details: details ? JSON.stringify(details) : null,
});

export const addPairEvidence = (
  pairs: Map<string, PairSignals>,
  left: CuratedEntity,
  right: CuratedEntity,
  detector: string,
  item: CurationEvidence,
) => {
  const key = pairKey(left.internal_id, right.internal_id);
  const existing = pairs.get(key);
  if (existing) {
    // One evidence per type: keep the strongest one.
    const sameType = existing.evidence.findIndex((e) => e.evidence_type === item.evidence_type);
    if (sameType === -1) {
      existing.evidence.push(item);
    } else if (existing.evidence[sameType].score * Math.abs(existing.evidence[sameType].weight) < item.score * Math.abs(item.weight)) {
      existing.evidence[sameType] = item;
    }
    existing.detectors.add(detector);
  } else {
    pairs.set(key, { left, right, evidence: [item], detectors: new Set([detector]) });
  }
};
// endregion

// region weights (documented in the user documentation: Curation > Detectors)
export const EVIDENCE_WEIGHTS = {
  canonicalFull: 0.92,
  canonicalStripped: 0.75,
  taxonomy: 0.8,
  trigram: 0.6,
  descriptionSimilarity: 0.45,
  graphSimilarity: 0.4,
  attackOverlap: 0.5,
  sharedTools: 0.3,
  sharedInfrastructure: 0.45,
  victimology: 0.2,
  coAttribution: 0.35,
  sourceDisagreement: 0.15,
  sameSource: -0.3,
};

const MIN_TECHNIQUES_FOR_OVERLAP = 3;
// endregion

// region detector 1 - normalization and alias graph
const NAME_BASED_EVIDENCE = [EVIDENCE_CANONICAL_COLLISION, EVIDENCE_SHARED_ALIAS, EVIDENCE_TAXONOMY, EVIDENCE_TRIGRAM, EVIDENCE_TYPE_COLLISION];
const isNameBased = (signals: PairSignals) => signals.evidence.some((e) => NAME_BASED_EVIDENCE.includes(e.evidence_type));

const hasCanonicalForm = (name: string, entityType: string, canonical: string) => {
  const forms = canonicalizeEntityNames([name], entityType);
  return forms.full.has(canonical) || forms.stripped.has(canonical);
};

const describeCollision = (left: CuratedEntity, right: CuratedEntity, canonical: string, stripped: boolean) => {
  const leftName = left.names.find((name) => hasCanonicalForm(name, left.entity_type, canonical)) ?? left.name;
  const rightName = right.names.find((name) => hasCanonicalForm(name, right.entity_type, canonical)) ?? right.name;
  const viaAlias = leftName !== left.name || rightName !== right.name;
  return { leftName, rightName, viaAlias, stripped };
};

/**
 * Canonical collisions between entities of the given list: same canonical form for a name or an alias.
 * Entities of the same type produce merge signals, entities of another type of the same family produce
 * type collision signals (for example a Malware and a Tool with the same name).
 */
export const detectCanonicalCollisions = (entities: CuratedEntity[], pairs: Map<string, PairSignals>) => {
  const fullIndex = new Map<string, CuratedEntity[]>();
  const strippedIndex = new Map<string, CuratedEntity[]>();
  entities.forEach((entity) => {
    entity.canonicals.full.forEach((canonical) => appendTo(fullIndex, canonical, entity));
    entity.canonicals.stripped.forEach((canonical) => appendTo(strippedIndex, canonical, entity));
  });
  const emit = (canonical: string, bucket: CuratedEntity[], stripped: boolean) => {
    // Very generic canonical forms shared by many entities are not a duplicate signal.
    if (bucket.length < 2 || bucket.length > 10) return;
    for (let i = 0; i < bucket.length; i += 1) {
      for (let j = i + 1; j < bucket.length; j += 1) {
        const left = bucket[i];
        const right = bucket[j];
        if (left.internal_id === right.internal_id) continue;
        const sameFamily = getTaxonomyFamily(left.entity_type) !== undefined && getTaxonomyFamily(left.entity_type) === getTaxonomyFamily(right.entity_type);
        if (left.entity_type !== right.entity_type && !sameFamily) continue;
        const info = describeCollision(left, right, canonical, stripped);
        const details = { canonical, left_name: info.leftName, right_name: info.rightName, stripped };
        if (left.entity_type !== right.entity_type) {
          addPairEvidence(pairs, left, right, DETECTOR_NORMALIZATION, evidence(
            EVIDENCE_TYPE_COLLISION,
            1,
            stripped ? EVIDENCE_WEIGHTS.canonicalStripped : EVIDENCE_WEIGHTS.canonicalFull,
            `"${info.leftName}" (${left.entity_type}) and "${info.rightName}" (${right.entity_type}) normalize to the same name "${canonical}" but have different types`,
            { ...details, left_type: left.entity_type, right_type: right.entity_type },
          ));
        } else {
          addPairEvidence(pairs, left, right, DETECTOR_NORMALIZATION, evidence(
            info.viaAlias ? EVIDENCE_SHARED_ALIAS : EVIDENCE_CANONICAL_COLLISION,
            1,
            stripped ? EVIDENCE_WEIGHTS.canonicalStripped : EVIDENCE_WEIGHTS.canonicalFull,
            stripped
              ? `"${info.leftName}" and "${info.rightName}" are the same name once vendor suffixes and qualifiers are removed ("${canonical}")`
              : `"${info.leftName}" and "${info.rightName}" normalize to the same name "${canonical}" (case, punctuation, separators, digits used as letters)`,
            details,
          ));
        }
      }
    }
  };
  fullIndex.forEach((bucket, canonical) => emit(canonical, bucket, false));
  strippedIndex.forEach((bucket, canonical) => {
    const merged = [...bucket, ...(fullIndex.get(canonical) ?? [])];
    const unique = merged.filter((entity, index) => merged.findIndex((e) => e.internal_id === entity.internal_id) === index);
    emit(canonical, unique, true);
  });
};

/**
 * Pairs of entities whose names belong to the same cluster of the vendor taxonomy (MITRE ATT&CK, MISP galaxy).
 */
export const detectTaxonomyPairs = (entities: CuratedEntity[], pairs: Map<string, PairSignals>) => {
  const byCluster = new Map<string, CuratedEntity[]>();
  entities.forEach((entity) => {
    const family = getTaxonomyFamily(entity.entity_type);
    if (!family) return;
    findTaxonomyClusters(entity.canonicals.full, family).forEach((cluster) => {
      const bucket = byCluster.get(cluster.ref);
      if (bucket) {
        if (!bucket.some((e) => e.internal_id === entity.internal_id)) bucket.push(entity);
      } else {
        byCluster.set(cluster.ref, [entity]);
      }
    });
  });
  byCluster.forEach((bucket) => {
    if (bucket.length < 2 || bucket.length > 10) return;
    for (let i = 0; i < bucket.length; i += 1) {
      for (let j = i + 1; j < bucket.length; j += 1) {
        const left = bucket[i];
        const right = bucket[j];
        const family = getTaxonomyFamily(left.entity_type) as TaxonomyFamily;
        if (getTaxonomyFamily(right.entity_type) !== family) continue;
        const match = findSharedTaxonomyCluster(
          family,
          { names: left.names, canonicals: left.canonicals.full, entityType: left.entity_type },
          { names: right.names, canonicals: right.canonicals.full, entityType: right.entity_type },
        );
        if (!match) continue;
        const reliability = getTaxonomySourceReliability(match.cluster.source);
        addPairEvidence(pairs, left, right, DETECTOR_NORMALIZATION, evidence(
          left.entity_type === right.entity_type ? EVIDENCE_TAXONOMY : EVIDENCE_TYPE_COLLISION,
          reliability,
          EVIDENCE_WEIGHTS.taxonomy,
          `"${match.leftName}" and "${match.rightName}" are listed as names of the same object by ${match.cluster.source === 'mitre' ? 'MITRE ATT&CK' : 'the MISP galaxy'} (${match.cluster.ref})`,
          { cluster: match.cluster.ref, source: match.cluster.source, left_name: match.leftName, right_name: match.rightName, cluster_names: match.cluster.names.slice(0, 20) },
        ));
      }
    }
  });
};

const MAX_PROPOSED_ALIASES = 40;
// Catalogue identifiers listed among the names (MITRE ATT&CK group, software and campaign ids): references, not names.
const CATALOGUE_IDENTIFIER = /^[GSC]\d{4}$/i;

const taxonomySourceName = (source: string) => (source === 'mitre' ? 'MITRE ATT&CK' : 'the MISP galaxy');

/**
 * Aliases the public name catalogues bundled with the platform (MITRE ATT&CK, MISP galaxy) give an entity and that it
 * does not carry yet, as one proposal per entity whatever the number of catalogues listing them. A name is never
 * proposed when it is carried by another entity (that becomes a merge or type mismatch proposal instead), when it is a
 * catalogue identifier, or when a catalogue also gives it to another object (a name shared by two actors identifies
 * neither). Names are owned by any of the given entities; aliases are only suggested for the focused ones when a focus
 * is given.
 */
export const detectMissingAliases = (entities: CuratedEntity[], focusIds?: Set<string>): ProposalDraft[] => {
  const knownCanonicals = new Map<string, Set<string>>();
  entities.forEach((entity) => entity.canonicals.full.forEach((canonical) => {
    const key = `${getTaxonomyFamily(entity.entity_type)}|${canonical}`;
    knownCanonicals.set(key, (knownCanonicals.get(key) ?? new Set<string>()).add(entity.internal_id));
  }));
  const drafts: ProposalDraft[] = [];
  entities.filter((entity) => !focusIds || focusIds.has(entity.internal_id)).forEach((entity) => {
    const family = getTaxonomyFamily(entity.entity_type);
    if (!family) return;
    const suggestions = suggestTaxonomyAliases(family, { names: entity.names, canonicals: entity.canonicals.full, entityType: entity.entity_type });
    const entityClusters = new Set(suggestions.map(({ cluster }) => cluster.ref));
    const canonicalOf = (alias: string) => [...canonicalizeEntityNames([alias], entity.entity_type).full];
    const isProposable = (alias: string) => {
      if (CATALOGUE_IDENTIFIER.test(alias.trim())) return false;
      const forms = canonicalOf(alias);
      const ownedElsewhere = forms.some((canonical) => {
        const owners = knownCanonicals.get(`${family}|${canonical}`) ?? new Set<string>();
        return [...owners].some((owner) => owner !== entity.internal_id);
      });
      const listedForAnotherObject = findTaxonomyClusters(forms, family).some((cluster) => !entityClusters.has(cluster.ref));
      return !ownedElsewhere && !listedForAnotherObject;
    };
    const catalogues = suggestions
      .map(({ cluster, aliases }) => ({ cluster, aliases: aliases.filter(isProposable) }))
      .filter(({ aliases }) => aliases.length > 0)
      .sort((left, right) => getTaxonomySourceReliability(right.cluster.source) - getTaxonomySourceReliability(left.cluster.source));
    if (catalogues.length === 0) return;
    // One spelling per name, the one of the most reliable catalogue.
    const proposed: string[] = [];
    const proposedCanonicals = new Set<string>();
    catalogues.forEach(({ aliases }) => aliases.forEach((alias) => {
      const forms = canonicalOf(alias);
      if (proposed.length >= MAX_PROPOSED_ALIASES || forms.some((canonical) => proposedCanonicals.has(canonical))) return;
      proposed.push(alias);
      forms.forEach((canonical) => proposedCanonicals.add(canonical));
    }));
    const listedBy = catalogues
      .map(({ cluster }) => ({ cluster, listed: proposed.filter((alias) => canonicalOf(alias).some((canonical) => cluster.canonicals.has(canonical))) }))
      .filter(({ listed }) => listed.length > 0);
    const items = listedBy.map(({ cluster, listed }) => {
      const matchedName = entity.names.find((name) => canonicalOf(name).some((canonical) => cluster.canonicals.has(canonical))) ?? entity.name;
      const source = taxonomySourceName(cluster.source);
      return evidence(
        EVIDENCE_TAXONOMY,
        getTaxonomySourceReliability(cluster.source),
        EVIDENCE_WEIGHTS.taxonomy,
        `${source.charAt(0).toUpperCase()}${source.slice(1)} (${cluster.ref}) lists ${listed.length} name(s) of "${entity.name}" that the entity does not carry yet`,
        { cluster: cluster.ref, source: cluster.source, aliases: listed, entity_name: entity.name, matched_name: matchedName },
      );
    });
    drafts.push({
      kind: PROPOSAL_KIND_ALIAS,
      detector: DETECTOR_NORMALIZATION,
      subjects: [{ id: entity.internal_id, entity_type: entity.entity_type, name: entity.name }],
      target_id: entity.internal_id,
      recommended_action: ACTION_ADD_ALIASES,
      action_payload: { aliases: proposed, cluster: listedBy[0].cluster.ref, clusters: listedBy.map(({ cluster }) => cluster.ref) },
      evidence: items,
      confidence: combineEvidence(items),
    });
  });
  return drafts;
};
// endregion

// region detector 2 - similarity
const MAX_TRIGRAM_POSTINGS = 400;

/**
 * Trigram similarity between names and aliases of entities of the same type, with an inverted index so that only
 * entities sharing trigrams are compared.
 */
export const detectTrigramPairs = (entities: CuratedEntity[], threshold: number, pairs: Map<string, PairSignals>) => {
  const index = new Map<string, Set<number>>();
  const gramsByEntity = entities.map((entity) => {
    const grams = new Set<string>();
    entity.names.forEach((name) => {
      const comparable = comparableName(name);
      if (comparable.replace(/ /g, '').length >= 5) trigrams(comparable).forEach((gram) => grams.add(gram));
    });
    return grams;
  });
  gramsByEntity.forEach((grams, position) => grams.forEach((gram) => {
    const postings = index.get(gram);
    if (postings) {
      postings.add(position);
    } else {
      index.set(gram, new Set([position]));
    }
  }));
  entities.forEach((entity, position) => {
    const shared = new Map<number, number>();
    gramsByEntity[position].forEach((gram) => {
      const postings = index.get(gram);
      if (!postings || postings.size > MAX_TRIGRAM_POSTINGS) return;
      postings.forEach((other) => {
        if (other > position && entities[other].entity_type === entity.entity_type) {
          shared.set(other, (shared.get(other) ?? 0) + 1);
        }
      });
    });
    shared.forEach((count, other) => {
      const minimum = Math.min(gramsByEntity[position].size, gramsByEntity[other].size);
      if (minimum === 0 || count / minimum < threshold * 0.6) return;
      const best = bestTrigramMatch(entity.names, entities[other].names);
      if (!best || best.score < threshold || best.score >= 1) return;
      addPairEvidence(pairs, entity, entities[other], DETECTOR_SIMILARITY, evidence(
        EVIDENCE_TRIGRAM,
        best.score,
        EVIDENCE_WEIGHTS.trigram,
        `"${best.left}" and "${best.right}" are ${Math.round(best.score * 100)}% similar (trigram similarity)`,
        { left_name: best.left, right_name: best.right, similarity: roundScore(best.score) },
      ));
    });
  });
};

/**
 * Description similarity (TF-IDF cosine within the entity type), only to reinforce or reveal pairs: descriptions
 * alone are never enough to create a proposal (see buildPairDraft).
 */
export const detectDescriptionPairs = (entities: CuratedEntity[], threshold: number, pairs: Map<string, PairSignals>) => {
  const byType = new Map<string, CuratedEntity[]>();
  entities.forEach((entity) => {
    if (!entity.description || entity.description.length < 80) return;
    appendTo(byType, entity.entity_type, entity);
  });
  byType.forEach((typed) => {
    const vectors = buildTfIdfVectors(typed.map((entity) => ({ id: entity.internal_id, text: (entity.description ?? '').slice(0, 4000) })));
    const index = new Map<string, number[]>();
    typed.forEach((entity, position) => {
      const vector = vectors.get(entity.internal_id);
      if (!vector) return;
      [...vector.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).forEach(([token]) => appendTo(index, token, position));
    });
    typed.forEach((entity, position) => {
      const vector = vectors.get(entity.internal_id);
      if (!vector) return;
      const candidates = new Set<number>();
      [...vector.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).forEach(([token]) => {
        const postings = index.get(token) ?? [];
        if (postings.length <= MAX_TRIGRAM_POSTINGS) postings.forEach((other) => {
          if (other > position) candidates.add(other);
        });
      });
      candidates.forEach((other) => {
        const otherVector = vectors.get(typed[other].internal_id);
        if (!otherVector) return;
        const score = sparseCosine(vector, otherVector);
        if (score < threshold) return;
        const terms = topSharedTerms(vector, otherVector);
        addPairEvidence(pairs, entity, typed[other], DETECTOR_SIMILARITY, evidence(
          EVIDENCE_DESCRIPTION_SIMILARITY,
          score,
          EVIDENCE_WEIGHTS.descriptionSimilarity,
          `The descriptions are ${Math.round(score * 100)}% similar (shared terms: ${terms.join(', ')})`,
          { similarity: roundScore(score), shared_terms: terms },
        ));
      });
    });
  });
};
// endregion

// region detector 3 - behavior anchoring
export const computeBehaviorEvidence = (left: NeighborSets, right: NeighborSets): CurationEvidence[] => {
  const items: CurationEvidence[] = [];
  if (left.techniques.size >= MIN_TECHNIQUES_FOR_OVERLAP && right.techniques.size >= MIN_TECHNIQUES_FOR_OVERLAP) {
    const score = jaccard(left.techniques, right.techniques);
    if (score > 0) {
      const shared = intersection(left.techniques, right.techniques);
      items.push(evidence(EVIDENCE_ATTACK_OVERLAP, score, EVIDENCE_WEIGHTS.attackOverlap,
        `${shared.length} ATT&CK techniques in common (${Math.round(score * 100)}% overlap of ${left.techniques.size} and ${right.techniques.size})`,
        { shared_ids: shared.slice(0, 50), shared_count: shared.length, left_count: left.techniques.size, right_count: right.techniques.size }));
    }
  }
  const setEvidence = (type: string, leftSet: Set<string>, rightSet: Set<string>, weight: number, label: string) => {
    if (leftSet.size === 0 || rightSet.size === 0) return;
    const score = jaccard(leftSet, rightSet);
    if (score <= 0) return;
    const shared = intersection(leftSet, rightSet);
    items.push(evidence(type, score, weight, `${shared.length} ${label} in common (${Math.round(score * 100)}% overlap)`, { shared_ids: shared.slice(0, 50), shared_count: shared.length }));
  };
  setEvidence(EVIDENCE_SHARED_TOOLS, left.tools, right.tools, EVIDENCE_WEIGHTS.sharedTools, 'tools or malware');
  setEvidence(EVIDENCE_SHARED_INFRASTRUCTURE, left.infrastructure, right.infrastructure, EVIDENCE_WEIGHTS.sharedInfrastructure, 'infrastructure elements');
  setEvidence(EVIDENCE_VICTIMOLOGY, left.victims, right.victims, EVIDENCE_WEIGHTS.victimology, 'targeted sectors, locations or organizations');
  const sharedCampaigns = intersection(left.campaigns, right.campaigns);
  if (sharedCampaigns.length > 0) {
    items.push(evidence(EVIDENCE_CO_ATTRIBUTION, Math.min(1, sharedCampaigns.length / 2), EVIDENCE_WEIGHTS.coAttribution,
      `${sharedCampaigns.length} campaign(s) or incident(s) attributed to both`, { shared_ids: sharedCampaigns.slice(0, 50), shared_count: sharedCampaigns.length }));
  }
  return items;
};

/**
 * Pairs of entities of the same type with a strongly overlapping ATT&CK technique set, found through an inverted
 * index on techniques. Very common techniques are ignored for candidate generation.
 */
export const detectBehaviorPairs = (
  entities: CuratedEntity[],
  neighbors: Map<string, NeighborSets>,
  threshold: number,
  pairs: Map<string, PairSignals>,
) => {
  const withTechniques = entities.filter((entity) => (neighbors.get(entity.internal_id)?.techniques.size ?? 0) >= 5);
  const postings = new Map<string, number[]>();
  withTechniques.forEach((entity, position) => {
    neighbors.get(entity.internal_id)?.techniques.forEach((technique) => appendTo(postings, technique, position));
  });
  const maxPostings = Math.max(10, Math.ceil(withTechniques.length * 0.3));
  withTechniques.forEach((entity, position) => {
    const shared = new Map<number, number>();
    neighbors.get(entity.internal_id)?.techniques.forEach((technique) => {
      const list = postings.get(technique) ?? [];
      if (list.length > maxPostings) return;
      list.forEach((other) => {
        if (other > position && withTechniques[other].entity_type === entity.entity_type) shared.set(other, (shared.get(other) ?? 0) + 1);
      });
    });
    shared.forEach((count, other) => {
      if (count < 5) return;
      const left = neighbors.get(entity.internal_id) as NeighborSets;
      const right = neighbors.get(withTechniques[other].internal_id) as NeighborSets;
      if (jaccard(left.techniques, right.techniques) < threshold) return;
      computeBehaviorEvidence(left, right).forEach((item) => addPairEvidence(pairs, entity, withTechniques[other], DETECTOR_BEHAVIOR, item));
    });
  });
};
// endregion

// region pair assembly
export interface PairContext {
  neighbors?: Map<string, NeighborSets>;
  graphSimilarity?: Map<string, { score: number; shared?: unknown }>;
  minConfidence: number;
  /** ATT&CK overlap a pair without any name signal must reach to be proposed. */
  behaviorThreshold: number;
}

const sourcesOf = (entity: CuratedEntity): Set<string> => (entity.created_by_id ? new Set([entity.created_by_id]) : new Set());

/**
 * Turn the collected signals of a pair into a proposal draft: merge for entities of the same type, type mismatch for
 * entities of the same family but different types. Returns null when the combined confidence is too low or when no
 * name-based or behavioral signal supports the pair.
 */
export const buildPairDraft = (signals: PairSignals, context: PairContext): ProposalDraft | null => {
  const { left, right } = signals;
  const items = [...signals.evidence];
  const isTypeMismatch = left.entity_type !== right.entity_type;
  if (!isTypeMismatch && context.neighbors) {
    const leftNeighbors = context.neighbors.get(left.internal_id);
    const rightNeighbors = context.neighbors.get(right.internal_id);
    if (leftNeighbors && rightNeighbors) {
      computeBehaviorEvidence(leftNeighbors, rightNeighbors).forEach((item) => {
        if (!items.some((existing) => existing.evidence_type === item.evidence_type)) {
          items.push(item);
          signals.detectors.add(DETECTOR_BEHAVIOR);
        }
      });
    }
  }
  const graph = context.graphSimilarity?.get(pairKey(left.internal_id, right.internal_id));
  if (graph && graph.score > 0) {
    items.push(evidence(EVIDENCE_GRAPH_SIMILARITY, graph.score, EVIDENCE_WEIGHTS.graphSimilarity,
      `Structural similarity of ${Math.round(graph.score * 100)}% in the knowledge graph analytics`, { shared: graph.shared ?? null }));
  }
  const leftSources = sourcesOf(left);
  const rightSources = sourcesOf(right);
  const hasExactCollision = items.some((item) => item.evidence_type === EVIDENCE_CANONICAL_COLLISION || item.evidence_type === EVIDENCE_SHARED_ALIAS);
  if (leftSources.size > 0 && rightSources.size > 0) {
    const sharedSources = intersection(leftSources, rightSources);
    if (sharedSources.length > 0 && !hasExactCollision) {
      items.push(evidence(EVIDENCE_SOURCE_AGREEMENT, sharedSources.length / Math.min(leftSources.size, rightSources.size), EVIDENCE_WEIGHTS.sameSource,
        'The same source maintains both entities separately, which suggests they are distinct', { shared_sources: sharedSources.slice(0, 20) }));
    } else if (sharedSources.length === 0) {
      items.push(evidence(EVIDENCE_SOURCE_AGREEMENT, 1, EVIDENCE_WEIGHTS.sourceDisagreement,
        'The entities come from different sources, a typical pattern of vendor naming', { left_sources: [...leftSources].slice(0, 10), right_sources: [...rightSources].slice(0, 10) }));
    }
  }
  const hasNameSignal = isNameBased({ ...signals, evidence: items });
  const behaviorScore = items.find((item) => item.evidence_type === EVIDENCE_ATTACK_OVERLAP)?.score ?? 0;
  if (!hasNameSignal && behaviorScore < context.behaviorThreshold) {
    return null;
  }
  const confidence = combineEvidence(items);
  if (confidence < context.minConfidence) {
    return null;
  }
  const detector = signals.detectors.size === 1 ? [...signals.detectors][0] : DETECTOR_COMBINED;
  return {
    kind: isTypeMismatch ? PROPOSAL_KIND_TYPE_MISMATCH : PROPOSAL_KIND_MERGE,
    detector,
    subjects: [
      { id: left.internal_id, entity_type: left.entity_type, name: left.name },
      { id: right.internal_id, entity_type: right.entity_type, name: right.name },
    ],
    target_id: null,
    recommended_action: isTypeMismatch ? ACTION_ACKNOWLEDGE : ACTION_MERGE,
    action_payload: null,
    evidence: items,
    confidence,
  };
};
// endregion

// region detector 4 - contradictions
export interface DatedElement {
  internal_id: string;
  entity_type: string;
  name: string;
  start_field: string;
  stop_field: string;
  start: string;
  stop: string;
}

export const buildDateInversionDraft = (element: DatedElement): ProposalDraft => {
  const item = evidence(EVIDENCE_DATE_INVERSION, 1, 0.95,
    `${element.start_field} (${element.start}) is after ${element.stop_field} (${element.stop})`,
    { start_field: element.start_field, stop_field: element.stop_field, start: element.start, stop: element.stop });
  return {
    kind: PROPOSAL_KIND_CONTRADICTION,
    detector: DETECTOR_CONTRADICTION,
    subjects: [{ id: element.internal_id, entity_type: element.entity_type, name: element.name }],
    target_id: element.internal_id,
    recommended_action: ACTION_FIX_DATES,
    action_payload: { start_field: element.start_field, stop_field: element.stop_field, start: element.start, stop: element.stop },
    evidence: [item],
    confidence: combineEvidence([item]),
  };
};

export interface AttributionConflict {
  attributed: { id: string; entity_type: string; name: string };
  actors: Array<{ id: string; entity_type: string; name: string; relationship_id: string }>;
}

export const buildAttributionConflictDraft = (conflict: AttributionConflict): ProposalDraft => {
  // An actor attributed twice (two time frames) is one subject, both of its attributions in the payload.
  const actorSubjects = conflict.actors
    .map(({ id, entity_type, name }) => ({ id, entity_type, name }))
    .filter((actor, index, all) => all.findIndex((other) => other.id === actor.id) === index);
  // Only names the proposal's readers can read: its subjects, never the authors of the attributions.
  const attributionsTo = actorSubjects.map((actor) => `"${actor.name}"`).join(' and to ');
  const item = evidence(EVIDENCE_ATTRIBUTION_CONFLICT, 1, 0.9,
    `"${conflict.attributed.name}" is attributed to ${attributionsTo}: these actors were decided to be distinct and no source attributes it to both`,
    {
      relationships: conflict.actors.map((actor) => ({ actor_id: actor.id, relationship_id: actor.relationship_id })),
      attributed_name: conflict.attributed.name,
      actor_names: actorSubjects.map((actor) => actor.name),
    });
  return {
    kind: PROPOSAL_KIND_CONTRADICTION,
    detector: DETECTOR_CONTRADICTION,
    subjects: [conflict.attributed, ...actorSubjects],
    target_id: conflict.attributed.id,
    recommended_action: ACTION_RESOLVE_ATTRIBUTION,
    action_payload: { attributed_id: conflict.attributed.id, relationships: conflict.actors.map((actor) => ({ actor_id: actor.id, relationship_id: actor.relationship_id })) },
    evidence: [item],
    confidence: combineEvidence([item]),
  };
};

export interface RevokedIndicatorConflict {
  indicator: { id: string; name: string; revoked_at?: string | null; valid_until?: string | null };
  observables: Array<{ id: string; entity_type: string; name: string; last_activity: string; score?: number | null }>;
}

export const buildRevokedIndicatorDraft = (conflict: RevokedIndicatorConflict): ProposalDraft => {
  const item = evidence(EVIDENCE_REVOKED_INDICATOR, 1, 0.8,
    `Indicator "${conflict.indicator.name}" is revoked while ${conflict.observables.length} observable(s) it is based on are still active`,
    {
      observables: conflict.observables.map((o) => ({ id: o.id, last_activity: o.last_activity, score: o.score ?? null })),
      valid_until: conflict.indicator.valid_until ?? null,
      indicator_name: conflict.indicator.name,
    });
  return {
    kind: PROPOSAL_KIND_CONTRADICTION,
    detector: DETECTOR_CONTRADICTION,
    subjects: [
      { id: conflict.indicator.id, entity_type: 'Indicator', name: conflict.indicator.name },
      ...conflict.observables.map((o) => ({ id: o.id, entity_type: o.entity_type, name: o.name })),
    ],
    target_id: conflict.indicator.id,
    recommended_action: ACTION_UNREVOKE_INDICATOR,
    action_payload: { indicator_id: conflict.indicator.id },
    evidence: [item],
    confidence: combineEvidence([item]),
  };
};

export const buildSplitDraft = (
  entity: { id: string; entity_type: string; name: string },
  mergeRecord: { id: string; source_names: string[] },
  contradiction: CurationEvidence,
): ProposalDraft => {
  const item = evidence(EVIDENCE_MERGED_ENTITY, 1, 0.6,
    `"${entity.name}" results from a merge with ${mergeRecord.source_names.map((n) => `"${n}"`).join(', ')} and is now involved in a contradiction`,
    { merge_record_id: mergeRecord.id, source_names: mergeRecord.source_names, entity_name: entity.name });
  return {
    kind: PROPOSAL_KIND_SPLIT,
    detector: DETECTOR_CONTRADICTION,
    subjects: [entity],
    target_id: entity.id,
    recommended_action: ACTION_UNMERGE,
    action_payload: { merge_record_id: mergeRecord.id },
    evidence: [item, contradiction],
    confidence: combineEvidence([item, contradiction]),
  };
};
// endregion

// region detector 5 - staleness
export interface StaleElement {
  internal_id: string;
  entity_type: string;
  name: string;
  /** No update and no new relationship over the staleness period: none for an indicator found by its decay alone. */
  inactivity?: { last_activity: string; months: number } | null;
  revoked: boolean;
  decayed?: { score: number; revoke_score: number } | null;
}

export const buildStaleDraft = (element: StaleElement): ProposalDraft => {
  const items: CurationEvidence[] = [];
  if (element.inactivity) {
    const { last_activity: lastActivity, months } = element.inactivity;
    items.push(evidence(EVIDENCE_STALENESS, Math.min(1, 0.6 + months / 120), 0.7,
      `No update and no new relationship since ${lastActivity.slice(0, 10)} (more than ${months} months)`,
      { last_activity: lastActivity, months }));
  }
  if (element.decayed) {
    items.push(evidence(EVIDENCE_DECAYED_INDICATOR, 1, 0.6,
      `The decayed score (${element.decayed.score}) is at or below the revoke score (${element.decayed.revoke_score}) but the indicator is still active`,
      { score: element.decayed.score, revoke_score: element.decayed.revoke_score }));
  }
  return {
    kind: PROPOSAL_KIND_STALE,
    detector: DETECTOR_STALENESS,
    subjects: [{ id: element.internal_id, entity_type: element.entity_type, name: element.name }],
    target_id: element.internal_id,
    recommended_action: ACTION_REVOKE,
    action_payload: { element_id: element.internal_id },
    evidence: items,
    confidence: combineEvidence(items),
  };
};
// endregion

// region detector 6 - relationship conflicts
export interface ProcedureConflict {
  relationship: { id: string; name: string; from_id: string; from_name: string; to_id: string; to_name: string };
  previous: { text: string; source_id: string | null };
  current: { text: string; source_id: string | null };
}

/** Duplicates come from the name normalization, similarity and behavior detectors: with all three off, none is looked for. */
export const isDuplicateDetectionEnabled = (settings: Pick<CurationSettings, 'curation_enabled' | 'enabled_detectors'>) => {
  const detectors = settings.enabled_detectors as string[];
  return settings.curation_enabled && [DETECTOR_NORMALIZATION, DETECTOR_SIMILARITY, DETECTOR_BEHAVIOR].some((detector) => detectors.includes(detector));
};

/** A decayed Indicator is due for revocation once its score reaches the revoke score of its decay rule, as the decay manager decides. */
export const isDecayedToRevocation = (indicator: Record<string, any>) => {
  const revokeScore = Number(indicator.decay_applied_rule?.decay_revoke_score);
  return Number.isFinite(revokeScore) && typeof indicator.x_opencti_score === 'number' && indicator.x_opencti_score <= revokeScore;
};

const ACTIVE_OBSERVABLE_MIN_SCORE = 50;

/**
 * When a revoked indicator was last revoked, so that its later edits do not move it: a manual revocation sets its end
 * of validity to that moment, an expiration revokes it at that end, and a decay revocation adds a point at the revoke
 * score to its decay history. Its last update is used only when none of them is known.
 */
export const indicatorRevocationTime = (indicator: Record<string, any>): number => {
  const candidates: number[] = [];
  const validUntil = indicator.valid_until ? new Date(indicator.valid_until).getTime() : Number.NaN;
  if (Number.isFinite(validUntil) && validUntil <= Date.now()) candidates.push(validUntil);
  const revokeScore = Number(indicator.decay_applied_rule?.decay_revoke_score);
  if (Number.isFinite(revokeScore)) {
    ((indicator.decay_history ?? []) as Array<{ score?: number; updated_at?: string | Date }>)
      .filter((point) => typeof point.score === 'number' && point.score <= revokeScore && point.updated_at)
      .forEach((point) => candidates.push(new Date(point.updated_at as string | Date).getTime()));
  }
  const known = candidates.filter((time) => Number.isFinite(time));
  return known.length > 0 ? Math.max(...known) : new Date(indicator.updated_at ?? 0).getTime();
};

/** The observables a revoked indicator is based on that were updated after its revocation with a score of 50 or more. */
export const observablesActiveSinceRevocation = <T extends Record<string, any>>(indicator: Record<string, any>, observables: Array<T | undefined>): T[] => {
  const revokedAt = indicatorRevocationTime(indicator);
  return observables.filter((observable): observable is T => !!observable
    && new Date(observable.updated_at ?? 0).getTime() > revokedAt
    && (observable.x_opencti_score ?? 0) >= ACTIVE_OBSERVABLE_MIN_SCORE);
};

const normalizeProcedure = (text: string) => text.replace(/\s+/g, ' ').trim().toLowerCase();

export const isProcedureConflict = (previousText: string | null | undefined, currentText: string | null | undefined) => {
  if (!previousText || !currentText) return false;
  const previous = normalizeProcedure(previousText);
  const current = normalizeProcedure(currentText);
  if (previous.length < 10 || current.length < 10 || previous === current) return false;
  // A pure extension (the new text contains the old one) is an enrichment, not a different procedure.
  return !current.includes(previous) && !previous.includes(current);
};

export const buildProcedureConflictDraft = (conflict: ProcedureConflict): ProposalDraft => {
  const item = evidence(EVIDENCE_PROCEDURE_CONFLICT, 1, 0.75,
    `The procedure of "${conflict.relationship.from_name} uses ${conflict.relationship.to_name}" was replaced by a different procedure from another source`,
    { previous: conflict.previous, current: conflict.current, from_name: conflict.relationship.from_name, to_name: conflict.relationship.to_name });
  return {
    kind: PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
    detector: DETECTOR_RELATIONSHIP_CONFLICT,
    subjects: [{ id: conflict.relationship.id, entity_type: 'uses', name: conflict.relationship.name }],
    target_id: conflict.relationship.id,
    recommended_action: ACTION_PRESERVE_PROCEDURE,
    action_payload: { relationship_id: conflict.relationship.id, previous: conflict.previous, current: conflict.current },
    evidence: [item],
    confidence: combineEvidence([item]),
  };
};
// endregion

// region merge target
export interface MergeTargetCandidate {
  id: string;
  relationships: number;
  names: number;
}

/** The surviving entity of a merge is the richest one (most relationships), then the one with the most names. */
export const selectMergeTarget = (candidates: MergeTargetCandidate[]): string | undefined => {
  const sorted = [...candidates].sort((a, b) => (b.relationships - a.relationships) || (b.names - a.names) || a.id.localeCompare(b.id));
  return sorted[0]?.id;
};
// endregion

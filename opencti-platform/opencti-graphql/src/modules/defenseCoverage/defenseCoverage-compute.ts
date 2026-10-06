import * as R from 'ramda';
import conf, { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../../database/middleware-loader';
import { elBulk, elRawDeleteByQuery, elUpdate, prepareElementForIndexing } from '../../database/engine';
import { buildEntityData } from '../../database/data-builder';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../../database/utils';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../schema/stixDomainObject';
import { RELATION_DETECTS, RELATION_HAS_COVERED, RELATION_INDICATES, RELATION_MITIGATES, RELATION_PROVIDES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR, type BasicStoreEntityIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, RELATION_RESULT_OF } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../schema/stixMetaObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { authorizedAuthorities, authorizedMembers } from '../../schema/attribute-definition';
import type { AuthorizedMember } from '../../utils/access';
import { doYield } from '../../utils/eventloop-utils';
import { now } from '../../utils/format';
import { FilterMode } from '../../generated/graphql';
import {
  DEFENSE_AGGREGATE_PLATFORM,
  DEFENSE_LEVEL_VALIDATED,
  DEFENSE_LIVE_DEPLOYMENT_STATUSES,
  DEFENSE_RULE_PATTERN_TYPES,
  type DefenseCoverage,
  type DefenseDeploymentEvidence,
  type DefenseEvidence,
  type DefensePlatformVector,
  type DefenseScore,
  type DefenseTelemetryEvidence,
  type DefenseValidationEvidence,
} from './defenseCoverage-types';
import { capEvidences, cellForPlatform, computeValidationStatus, evaluateCoverage, type LogsourceCondition, mapLogsourceToDataComponents } from './defenseCoverage-utils';
import { listAllDefenseLogsourceMappings } from './defenseLogsourceMapping/defenseLogsourceMapping-domain';
import { DEFENSE_GAP_STATUS_CLOSED, DEFENSE_GAP_STATUS_OPEN, ENTITY_TYPE_DEFENSE_GAP, type BasicStoreEntityDefenseGap } from './defenseGap/defenseGap-types';
import { bumpDefenseCoverageVersion, queuePendingLevelChanges } from './defenseCoverage-state';
import { collectDefenseCoverageChanges, deliverPendingDefenseLevelChanges } from './defenseCoverage-notification';
import { generateStandardId } from '../../schema/identifier';

const VALIDATION_SUCCESS_THRESHOLD = conf.get('defense_coverage_manager:validation_success_threshold') ?? 50;
const MAX_EVIDENCES = conf.get('defense_coverage_manager:max_evidences') ?? 250;
// Hard bound of the stored access partitions of an evidence list, whatever their number
const MAX_EVIDENCE_PARTITIONS = conf.get('defense_coverage_manager:max_evidence_partitions') ?? 1000;
const BULK_SIZE = 500;
const IDS_CHUNK_SIZE = 5000;

// Access fields of an evidence element that the base fields do not return, read by its access signature
const EVIDENCE_ACCESS_FIELDS = [authorizedAuthorities.name];
const AP_BASE_FIELDS = ['name', 'x_mitre_id', 'revoked', 'x_opencti_defense_coverage'];
const INDICATOR_BASE_FIELDS = ['name', 'pattern_type', 'revoked', 'x_opencti_rule_logsource', 'x_opencti_rule_status', 'x_opencti_rule_level', ...EVIDENCE_ACCESS_FIELDS];

export interface DefensePlatform {
  id: string;
  name: string;
  entity_type: string;
  security_platform_type?: string;
  stix_ids: string[];
}

export interface DefenseComputationResult {
  techniques: number;
  updated: number;
  cleared: number;
  level_changes: number;
  notified: number;
  gaps: number;
  // Gaps whose computed values changed, the only ones written
  written_gaps: number;
  closed_gaps: number;
  platforms: number;
  duration: number;
}

const chunkIds = (ids: string[]) => R.splitEvery(IDS_CHUNK_SIZE, ids);

const findByIdsChunked = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, ids: string[], opts: Record<string, any>) => {
  const results: T[] = [];
  const chunks = chunkIds(R.uniq(ids));
  for (let index = 0; index < chunks.length; index += 1) {
    const found = await internalFindByIds<T>(context, user, chunks[index], opts) as T[];
    results.push(...found);
  }
  return results;
};

const groupBy = <T>(items: T[], key: (item: T) => string) => {
  const map = new Map<string, T[]>();
  items.forEach((item) => {
    const k = key(item);
    const list = map.get(k);
    if (list) list.push(item);
    else map.set(k, [item]);
  });
  return map;
};

// region loading
export const loadDefensePlatforms = async (context: AuthContext, user: AuthUser): Promise<DefensePlatform[]> => {
  const securityPlatforms = await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], {
    baseData: true,
    baseFields: ['name', 'x_opencti_stix_ids', 'security_platform_type'],
  });
  const systemProvides = await fullRelationsList<BasicStoreRelation>(context, user, RELATION_PROVIDES, {
    fromTypes: [ENTITY_TYPE_IDENTITY_SYSTEM],
    baseData: true,
  });
  const systemIds = R.uniq(systemProvides.map((r) => r.fromId));
  const systems = systemIds.length > 0
    ? await findByIdsChunked<BasicStoreEntity>(context, user, systemIds, { type: ENTITY_TYPE_IDENTITY_SYSTEM, baseData: true, baseFields: ['name', 'x_opencti_stix_ids'] })
    : [];
  return [...securityPlatforms, ...systems].map((p) => ({
    id: p.internal_id,
    name: p.name,
    entity_type: p.entity_type,
    security_platform_type: (p as unknown as { security_platform_type?: string }).security_platform_type,
    stix_ids: [p.standard_id, ...(p.x_opencti_stix_ids ?? [])],
  })).sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''));
};

const loadAttackPatterns = async (context: AuthContext, user: AuthUser, attackPatternIds?: string[]) => {
  const opts = {
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    baseData: true,
    baseFields: AP_BASE_FIELDS,
  };
  if (attackPatternIds) {
    return findByIdsChunked<BasicStoreEntity>(context, user, attackPatternIds, { ...opts, type: ENTITY_TYPE_ATTACK_PATTERN });
  }
  return fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_ATTACK_PATTERN], opts);
};

const loadRelationsToTechniques = async (
  context: AuthContext,
  user: AuthUser,
  relationshipType: string,
  fromTypes: string[],
  attackPatternIds: string[] | undefined,
  baseFields: string[] = [],
) => {
  const args = { fromTypes, toTypes: [ENTITY_TYPE_ATTACK_PATTERN], baseData: true, baseFields: [...baseFields, ...EVIDENCE_ACCESS_FIELDS] };
  if (!attackPatternIds) {
    return fullRelationsList<BasicStoreRelation>(context, user, relationshipType, args);
  }
  const relations: BasicStoreRelation[] = [];
  const chunks = chunkIds(attackPatternIds);
  for (let index = 0; index < chunks.length; index += 1) {
    const found = await fullRelationsList<BasicStoreRelation>(context, user, relationshipType, { ...args, toId: chunks[index] });
    relations.push(...found);
  }
  return relations;
};
// endregion

// region vector building
export interface ComputationGraph {
  platforms: DefensePlatform[];
  platformIdByStixId: Map<string, string>;
  detectsByTechnique: Map<string, BasicStoreRelation[]>;
  providesByDataComponent: Map<string, BasicStoreRelation[]>;
  indicatesByTechnique: Map<string, BasicStoreRelation[]>;
  rulesById: Map<string, BasicStoreEntityIndicator>;
  // Relationships from a rule to the security platforms it is deployed on, with their deployment_status. The platform
  // records none yet: a known rule is a detection available, deployment unknown.
  deploymentsByRule?: Map<string, BasicStoreRelation[]>;
  mitigatesByTechnique: Map<string, BasicStoreRelation[]>;
  hasCoveredByTechnique: Map<string, BasicStoreRelation[]>;
  resultsById: Map<string, BasicStoreEntity>;
  dataComponentIdsByName: Map<string, string[]>;
  mappings: LogsourceCondition[];
  // Access signature of every loaded evidence element: markings and granted organizations come with every load
  // (security doc values), restricted members with the base fields, authorities with EVIDENCE_ACCESS_FIELDS
  accessKeyById?: Map<string, string>;
}

const sortedIds = (values: string[] | null | undefined, separator: string) => [...(values ?? [])].sort().join(separator);

// Every dimension the access check reads: two elements share a signature only if every reader has the same access to both
export const accessSignature = (element: BasicStoreEntity | BasicStoreRelation) => {
  const data = element as unknown as Record<string, string[] | undefined>;
  // Stored elements hold their member restrictions under restricted_members (authorized_members is the input name);
  // a member with groups restriction ids only grants its access to users of all these groups
  const members = ((data[authorizedMembers.name] as unknown as AuthorizedMember[] | undefined) ?? [])
    .map((member) => `${member.id}:${member.access_right}:${sortedIds(member.groups_restriction_ids, '+')}`)
    .sort()
    .join(',');
  const authorities = sortedIds(data[authorizedAuthorities.name], ',');
  return `${sortedIds(data[RELATION_OBJECT_MARKING], ',')};${sortedIds(data[RELATION_GRANTED_TO], ',')};${members};${authorities}`;
};

const buildAccessKeys = (elements: Array<BasicStoreEntity | BasicStoreRelation>) => {
  const keys = new Map<string, string>();
  elements.forEach((element) => keys.set(element.internal_id, accessSignature(element)));
  return keys;
};

type EvidenceRefs = { id: string; rel: string; detects?: string; inferred_from?: string; indicates?: string };
const evidenceAccessKey = (graph: ComputationGraph) => {
  const { accessKeyById } = graph;
  if (!accessKeyById) return undefined;
  return (evidence: EvidenceRefs) => [evidence.id, evidence.rel, evidence.detects, evidence.inferred_from, evidence.indicates]
    .map((id) => (id ? accessKeyById.get(id) ?? '' : ''))
    .join('|');
};

const relationScores = (relation: BasicStoreRelation): DefenseScore[] => {
  const information = (relation as unknown as { coverage_information?: { coverage_name: string; coverage_score: number }[] }).coverage_information ?? [];
  return information.map((c) => ({ name: c.coverage_name, score: c.coverage_score }));
};

const relationPlatformScores = (relation: BasicStoreRelation) => {
  const information = (relation as unknown as { coverage_platforms_information?: { platform_ref: string; coverage_name: string; coverage_score: number }[] })
    .coverage_platforms_information ?? [];
  return groupBy(information, (c) => c.platform_ref);
};

// OpenAEV scoped the result to platforms: it never counts technique-wide, even when none of them resolves here
const hasPlatformAttribution = (relation: BasicStoreRelation) => Array.from(relationPlatformScores(relation).keys()).some((platformRef) => !!platformRef);

const resultDate = (result: BasicStoreEntity | undefined, relation: BasicStoreRelation) => {
  const lastResult = (result as unknown as { coverage_last_result?: string } | undefined)?.coverage_last_result;
  return lastResult ?? (relation as unknown as { updated_at?: string }).updated_at ?? undefined;
};

const resultCoverageId = (result: BasicStoreEntity | undefined) => {
  // result-of is a single ref: a loaded result holds the id itself, not a list
  const ref = (result as unknown as Record<string, string | string[] | undefined> | undefined)?.[RELATION_RESULT_OF];
  return Array.isArray(ref) ? ref[0] : ref;
};

export const buildTechniqueCoverage = (attackPatternId: string, graph: ComputationGraph, computedAt: string): DefenseCoverage => {
  const detects = graph.detectsByTechnique.get(attackPatternId) ?? [];
  const indicates = (graph.indicatesByTechnique.get(attackPatternId) ?? []).filter((r) => graph.rulesById.has(r.fromId));
  const mitigates = graph.mitigatesByTechnique.get(attackPatternId) ?? [];
  const hasCovered = graph.hasCoveredByTechnique.get(attackPatternId) ?? [];
  const detectsByDataComponent = groupBy(detects, (d) => d.fromId);

  const dataComponents: DefenseEvidence[] = detects.map((d) => ({ id: d.fromId, rel: d.id }));
  const rules: DefenseEvidence[] = indicates.map((i) => ({ id: i.fromId, rel: i.id }));
  const mitigations: DefenseEvidence[] = mitigates.map((m) => ({ id: m.fromId, rel: m.id }));
  const validations: DefenseValidationEvidence[] = hasCovered.map((h) => {
    const result = graph.resultsById.get(h.fromId);
    const scores = relationScores(h);
    return {
      id: h.fromId,
      rel: h.id,
      coverage_id: resultCoverageId(result),
      status: computeValidationStatus(scores, VALIDATION_SUCCESS_THRESHOLD),
      last_result_at: resultDate(result, h),
      scores,
    };
  });

  const vectors = new Map<string, DefensePlatformVector>();
  const vectorOf = (platformId: string) => {
    let vector = vectors.get(platformId);
    if (!vector) {
      vector = { platform_id: platformId, telemetry: [], deployments: [], validations: [], level: 0 };
      vectors.set(platformId, vector);
    }
    return vector;
  };
  const platformIds = new Set(graph.platforms.map((p) => p.id));

  // Telemetry declared through provides
  detects.forEach((detect) => {
    const provides = graph.providesByDataComponent.get(detect.fromId) ?? [];
    provides.filter((p) => platformIds.has(p.fromId)).forEach((p) => {
      vectorOf(p.fromId).telemetry.push({ id: detect.fromId, rel: p.id, detects: detect.id } as DefenseTelemetryEvidence);
    });
  });

  // Deployed rules, and the telemetry they imply through their log source
  indicates.forEach((indicate) => {
    const rule = graph.rulesById.get(indicate.fromId) as BasicStoreEntityIndicator;
    const deployments = graph.deploymentsByRule?.get(indicate.fromId) ?? [];
    const requiredNames = mapLogsourceToDataComponents(rule.x_opencti_rule_logsource, graph.mappings);
    const requiredIds = new Set(requiredNames.flatMap((name) => graph.dataComponentIdsByName.get(name.toLowerCase()) ?? []));
    deployments.filter((d) => platformIds.has(d.toId)).forEach((deployment) => {
      const vector = vectorOf(deployment.toId);
      const status = (deployment as unknown as { deployment_status?: string }).deployment_status ?? 'deployed';
      vector.deployments.push({ id: indicate.fromId, rel: deployment.id, status, indicates: indicate.id } as DefenseDeploymentEvidence);
      // Only a rule running on the platform proves that the platform collects its log source
      if (!DEFENSE_LIVE_DEPLOYMENT_STATUSES.includes(status)) return;
      requiredIds.forEach((dataComponentId) => {
        (detectsByDataComponent.get(dataComponentId) ?? []).forEach((detect) => {
          vector.telemetry.push({ id: dataComponentId, rel: deployment.id, detects: detect.id, inferred_from: indicate.fromId, indicates: indicate.id });
        });
      });
    });
  });

  // OpenAEV results attributed to a security platform
  hasCovered.forEach((h, index) => {
    const result = graph.resultsById.get(h.fromId);
    relationPlatformScores(h).forEach((entries, platformRef) => {
      const platformId = graph.platformIdByStixId.get(platformRef) ?? (platformIds.has(platformRef) ? platformRef : undefined);
      if (!platformId) return;
      const scores = entries.map((e) => ({ name: e.coverage_name, score: e.coverage_score }));
      vectorOf(platformId).validations.push({
        id: h.fromId,
        rel: h.id,
        coverage_id: resultCoverageId(result),
        status: computeValidationStatus(scores, VALIDATION_SUCCESS_THRESHOLD),
        last_result_at: validations[index].last_result_at,
        scores,
      });
    });
  });

  const accessKey = evidenceAccessKey(graph);
  // The latest result of a partition is the one a reader's level depends on: it comes first and is always kept
  const latestFirst = <T extends DefenseValidationEvidence>(list: T[]) => R.sortWith<T>([R.descend((v) => v.last_result_at ?? '')], list);
  const attributedRels = new Set(hasCovered.filter(hasPlatformAttribution).map((h) => h.id));
  const platforms = Array.from(vectors.values()).map((vector) => ({
    ...vector,
    telemetry: capEvidences(R.uniqBy((t) => `${t.id}|${t.rel}|${t.detects}`, vector.telemetry), MAX_EVIDENCES, accessKey, undefined, MAX_EVIDENCE_PARTITIONS),
    deployments: capEvidences(vector.deployments, MAX_EVIDENCES, accessKey, (d) => d.status, MAX_EVIDENCE_PARTITIONS),
    validations: capEvidences(latestFirst(vector.validations), MAX_EVIDENCES, accessKey, undefined, MAX_EVIDENCE_PARTITIONS),
  }));
  const coverage: DefenseCoverage = {
    computed_at: computedAt,
    data_components: capEvidences(dataComponents, MAX_EVIDENCES, accessKey, undefined, MAX_EVIDENCE_PARTITIONS),
    rules: capEvidences(rules, MAX_EVIDENCES, accessKey, undefined, MAX_EVIDENCE_PARTITIONS),
    mitigations: capEvidences(mitigations, MAX_EVIDENCES, accessKey, undefined, MAX_EVIDENCE_PARTITIONS),
    validations: capEvidences(latestFirst(validations.map((v) => ({ ...v, attributed: attributedRels.has(v.rel) }))), MAX_EVIDENCES, accessKey, undefined, MAX_EVIDENCE_PARTITIONS),
    platforms,
    level: 0,
  };
  // Stored levels are the system view, every evidence being visible
  const cell = evaluateCoverage(attackPatternId, coverage, () => true);
  coverage.level = cell.level;
  coverage.platforms = platforms.map((p) => ({ ...p, level: cellForPlatform(cell, p.platform_id).level }));
  return coverage;
};
// endregion

// region storage
const COVERAGE_UPDATE_SCRIPT = 'ctx._source.x_opencti_defense_coverage = params.coverage;';
const COVERAGE_CLEAR_SCRIPT = 'ctx._source.remove(\'x_opencti_defense_coverage\');';

const coverageSignature = (coverage: DefenseCoverage | undefined | null) => {
  if (!coverage) return '';
  const { computed_at: _computedAt, ...content } = coverage;
  return JSON.stringify(content);
};

/**
 * Store the coverage of one technique directly in the engine: no stream event, no history, no updated_at change.
 */
export const updateAttackPatternDefenseCoverage = async (context: AuthContext, attackPattern: BasicStoreEntity, coverage: DefenseCoverage) => {
  return elUpdate(context, attackPattern._index, attackPattern.internal_id, {
    script: { source: COVERAGE_UPDATE_SCRIPT, lang: 'painless', params: { coverage } },
  });
};

/**
 * Remove the stored coverage of revoked techniques: they leave the matrix, and nothing must keep reading them as covered.
 */
const clearRevokedCoverages = async (context: AuthContext, attackPatterns: BasicStoreEntity[]) => {
  const stored = attackPatterns.filter((ap) => !!(ap as unknown as { x_opencti_defense_coverage?: DefenseCoverage }).x_opencti_defense_coverage);
  const groups = R.splitEvery(BULK_SIZE, stored);
  for (let index = 0; index < groups.length; index += 1) {
    const body = groups[index].flatMap((attackPattern) => [
      { update: { _index: attackPattern._index, _id: attackPattern.internal_id, retry_on_conflict: 5 } },
      { script: { source: COVERAGE_CLEAR_SCRIPT, lang: 'painless' } },
    ]);
    await elBulk(context, { refresh: true, body });
  }
  return stored.length;
};

const bulkUpdateCoverages = async (context: AuthContext, updates: Array<{ attackPattern: BasicStoreEntity; coverage: DefenseCoverage }>) => {
  if (updates.length <= 1) {
    for (let index = 0; index < updates.length; index += 1) {
      await updateAttackPatternDefenseCoverage(context, updates[index].attackPattern, updates[index].coverage);
    }
    return;
  }
  const groups = R.splitEvery(BULK_SIZE, updates);
  for (let index = 0; index < groups.length; index += 1) {
    const body = groups[index].flatMap(({ attackPattern, coverage }) => [
      { update: { _index: attackPattern._index, _id: attackPattern.internal_id, retry_on_conflict: 5 } },
      { script: { source: COVERAGE_UPDATE_SCRIPT, lang: 'painless', params: { coverage } } },
    ]);
    await elBulk(context, { refresh: true, body });
  }
};

export const defenseGapId = (attackPatternId: string, platformId: string) => {
  const standardId = generateStandardId(ENTITY_TYPE_DEFENSE_GAP, { attack_pattern_id: attackPatternId, platform_id: platformId });
  return { standardId, internalId: standardId.split('--')[1] };
};

// Fields of a gap written by the validation requests, never by the computation of an existing gap
const GAP_LIFECYCLE_FIELDS = ['validation_requests', 'last_validation_requested_at'];
// Computed fields a gap may lose (a reopened gap has no closed_at any more)
const GAP_OPTIONAL_COMPUTED_FIELDS = ['closed_at', 'x_mitre_id'];
const GAP_REFRESH_SCRIPT = `
  for (entry in params.computed.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }
  for (field in params.removed) { ctx._source.remove(field); }
`;
// Techniques whose gaps are prepared and written together, so a full run holds this many techniques times the number
// of security platforms in memory, whatever the size of the matrix
const GAP_CHUNK_TECHNIQUES = 100;
// The computed values of a gap: a stored gap holding the same ones is not written again
const GAP_COMPARED_FIELDS = ['name', 'attack_pattern_id', 'platform_id', 'x_mitre_id', 'level', 'recommended_action', 'status', 'opened_at', 'closed_at'];

const isGapUnchanged = (previous: BasicStoreEntityDefenseGap, input: Record<string, unknown>) => {
  const stored = previous as unknown as Record<string, unknown>;
  return GAP_COMPARED_FIELDS.every((field) => (stored[field] ?? null) === (input[field] ?? null));
};

/**
 * Write the gap of every technique and platform pair, by chunks of techniques, skipping the gaps whose computed values
 * did not change. Only the last bulk of the run refreshes the index: no batch of the run reads the gaps of another one.
 */
const storeGaps = async (
  context: AuthContext,
  user: AuthUser,
  entries: Array<{ attackPattern: BasicStoreEntity; coverage: DefenseCoverage }>,
  platformKeys: string[],
  platforms: DefensePlatform[],
  computedAt: string,
) => {
  const platformNames = new Map(platforms.map((p) => [p.id, p.name]));
  let closed = 0;
  let written = 0;
  let pendingBody: unknown[] | undefined;
  const flush = async (refresh: boolean) => {
    if (pendingBody) await elBulk(context, { refresh, body: pendingBody });
    pendingBody = undefined;
  };
  const chunks = R.splitEvery(GAP_CHUNK_TECHNIQUES, entries);
  for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += 1) {
    const wanted = chunks[chunkIndex].flatMap(({ attackPattern, coverage }) => {
      const cell = evaluateCoverage(attackPattern.internal_id, coverage, () => true);
      return platformKeys.map((platformId) => ({
        attackPattern,
        platformId,
        cellPlatform: cellForPlatform(cell, platformId),
        ...defenseGapId(attackPattern.internal_id, platformId),
      }));
    });
    const existing = await findByIdsChunked<BasicStoreEntityDefenseGap>(context, user, wanted.map((w) => w.internalId), {
      type: ENTITY_TYPE_DEFENSE_GAP,
      indices: [READ_INDEX_INTERNAL_OBJECTS],
    });
    const existingById = new Map(existing.map((e) => [e.internal_id, e]));
    const docs: Array<{ element: Record<string, unknown>; previousIndex?: string }> = [];
    for (let index = 0; index < wanted.length; index += 1) {
      await doYield();
      const { attackPattern, platformId, cellPlatform, standardId, internalId } = wanted[index];
      const previous = existingById.get(internalId);
      const isClosed = cellPlatform.level >= DEFENSE_LEVEL_VALIDATED;
      // Only an actual open -> closed transition counts, not a technique already validated at its first computation
      if (isClosed && previous?.status === DEFENSE_GAP_STATUS_OPEN) closed += 1;
      const platformName = platformId === DEFENSE_AGGREGATE_PLATFORM ? 'All platforms' : (platformNames.get(platformId) ?? platformId);
      const input = {
        internal_id: internalId,
        standard_id: standardId,
        entity_type: ENTITY_TYPE_DEFENSE_GAP,
        name: `${attackPattern.x_mitre_id ? `[${attackPattern.x_mitre_id}] ` : ''}${attackPattern.name} - ${platformName}`,
        attack_pattern_id: attackPattern.internal_id,
        platform_id: platformId,
        x_mitre_id: attackPattern.x_mitre_id,
        level: cellPlatform.level,
        recommended_action: cellPlatform.recommended_action,
        status: isClosed ? DEFENSE_GAP_STATUS_CLOSED : DEFENSE_GAP_STATUS_OPEN,
        opened_at: previous?.opened_at ?? computedAt,
        closed_at: isClosed ? (previous?.closed_at ?? computedAt) : undefined,
        computed_at: computedAt,
        validation_requests: previous?.validation_requests ?? [],
        last_validation_requested_at: previous?.last_validation_requested_at,
        created_at: previous?.created_at ?? computedAt,
        updated_at: computedAt,
      };
      if (!previous || !isGapUnchanged(previous, input)) {
        const { element } = await buildEntityData(context, user, R.reject(R.isNil, input), ENTITY_TYPE_DEFENSE_GAP);
        docs.push({ element: await prepareElementForIndexing(element), previousIndex: previous?._index });
      }
    }
    // A validation request is appended to its gaps without the computation lock: an existing gap gets the computed
    // fields only, so that a request appended since it was read is never replaced by the copy taken above
    const groups = R.splitEvery(BULK_SIZE, docs);
    for (let index = 0; index < groups.length; index += 1) {
      const body = groups[index].flatMap(({ element, previousIndex }) => {
        const { _index: _ignored, ...upsert } = element;
        const computed = R.omit(GAP_LIFECYCLE_FIELDS, upsert);
        const removed = GAP_OPTIONAL_COMPUTED_FIELDS.filter((field) => !(field in computed));
        return [
          { update: { _index: previousIndex ?? INDEX_INTERNAL_OBJECTS, _id: upsert.internal_id, retry_on_conflict: 5 } },
          { script: { source: GAP_REFRESH_SCRIPT, lang: 'painless', params: { computed, removed } }, upsert },
        ];
      });
      await flush(false);
      pendingBody = body;
    }
    written += docs.length;
  }
  await flush(true);
  return { gaps: entries.length * platformKeys.length, written, closed };
};

/**
 * Whether a run over the given techniques and platforms produces the gap: its id is derived from its technique and
 * platform, so a gap the run produces is recognized without keeping the id of every gap of the run.
 */
export const isProducedGap = (
  gap: { internal_id: string; attack_pattern_id?: string; platform_id?: string },
  techniqueIds: Set<string>,
  platformKeys: Set<string>,
) => {
  if (!gap.attack_pattern_id || !gap.platform_id) return false;
  if (!techniqueIds.has(gap.attack_pattern_id) || !platformKeys.has(gap.platform_id)) return false;
  return defenseGapId(gap.attack_pattern_id, gap.platform_id).internalId === gap.internal_id;
};

/**
 * After a full run, delete the gaps the run did not produce (a revoked or deleted technique, a removed platform),
 * except the ones written since the run started (a gap created meanwhile by a validation request).
 * The stored gaps are read and deleted page by page.
 */
const deleteStaleGaps = async (context: AuthContext, user: AuthUser, techniqueIds: Set<string>, platformKeys: Set<string>, computedAt: string) => {
  let deleted = 0;
  await fullEntitiesList<BasicStoreEntityDefenseGap>(context, user, [ENTITY_TYPE_DEFENSE_GAP], {
    baseData: true,
    baseFields: ['internal_id', 'attack_pattern_id', 'platform_id', 'computed_at'],
    first: BULK_SIZE,
    callback: async (page: BasicStoreEntityDefenseGap[]) => {
      const staleIds = page
        .filter((gap) => !isProducedGap(gap, techniqueIds, platformKeys) && (gap.computed_at ?? '') < computedAt)
        .map((gap) => gap.internal_id);
      if (staleIds.length > 0) {
        await elRawDeleteByQuery({
          index: READ_INDEX_INTERNAL_OBJECTS,
          refresh: true,
          wait_for_completion: true,
          body: {
            query: {
              bool: {
                filter: [
                  { term: { 'entity_type.keyword': ENTITY_TYPE_DEFENSE_GAP } },
                  { terms: { 'internal_id.keyword': staleIds } },
                ],
              },
            },
          },
        });
        deleted += staleIds.length;
      }
      return true;
    },
  } as never);
  return deleted;
};

const deleteGapsOfTechniques = async (attackPatternIds: string[]) => {
  if (attackPatternIds.length === 0) return;
  await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    wait_for_completion: true,
    body: {
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': ENTITY_TYPE_DEFENSE_GAP } },
            { terms: { 'attack_pattern_id.keyword': attackPatternIds } },
          ],
        },
      },
    },
  });
};
// endregion

/** Drop the revoked data components, the techniques they detect and the telemetry provided on them. */
export const withoutRevokedDataComponents = (
  dataComponents: BasicStoreEntity[],
  detects: BasicStoreRelation[],
  provides: BasicStoreRelation[],
) => {
  const revokedIds = new Set(dataComponents.filter((dc) => dc.revoked).map((dc) => dc.internal_id));
  return {
    dataComponents: dataComponents.filter((dc) => !dc.revoked),
    detects: detects.filter((relation) => !revokedIds.has(relation.fromId)),
    provides: provides.filter((relation) => !revokedIds.has(relation.toId)),
  };
};

/** Keep the mitigations of the loaded courses of action that are not revoked. */
export const activeMitigations = (mitigates: BasicStoreRelation[], coursesOfAction: BasicStoreEntity[]) => {
  const activeIds = new Set(coursesOfAction.filter((coa) => !coa.revoked).map((coa) => coa.internal_id));
  return mitigates.filter((relation) => activeIds.has(relation.fromId));
};

/** Keep the OpenAEV results that hold at the given date: not revoked, already valid and not expired. */
export const currentCoverageResults = <T extends BasicStoreEntity>(results: T[], at: string) => {
  const time = new Date(at).getTime();
  return results.filter((result) => {
    const { coverage_valid_from: validFrom, coverage_valid_to: validTo } = result as unknown as { coverage_valid_from?: string; coverage_valid_to?: string };
    if (result.revoked) return false;
    if (validFrom && new Date(validFrom).getTime() > time) return false;
    return !(validTo && new Date(validTo).getTime() < time);
  });
};

/**
 * Compute and store the defense coverage of every technique (full run) or of the given techniques (incremental run).
 * The computation runs with the given user (the manager uses the system user) and stores only ids:
 * readers re-evaluate the coverage with their own access.
 */
export const computeDefenseCoverage = async (
  context: AuthContext,
  user: AuthUser,
  opts: { attackPatternIds?: string[] } = {},
): Promise<DefenseComputationResult> => {
  const start = Date.now();
  const computedAt = now();
  const isFull = !opts.attackPatternIds;
  const targetIds = opts.attackPatternIds ? R.uniq(opts.attackPatternIds) : undefined;

  // 1. Techniques and platforms
  const attackPatterns = await loadAttackPatterns(context, user, targetIds);
  const activeAttackPatterns = attackPatterns.filter((ap) => !ap.revoked);
  const revokedAttackPatterns = attackPatterns.filter((ap) => ap.revoked);
  const revokedIds = revokedAttackPatterns.map((ap) => ap.internal_id);
  const techniqueIds = activeAttackPatterns.map((ap) => ap.internal_id);
  const scopedIds = isFull ? undefined : techniqueIds;
  const platforms = await loadDefensePlatforms(context, user);
  const platformIdByStixId = new Map<string, string>();
  platforms.forEach((p) => p.stix_ids.forEach((stixId) => platformIdByStixId.set(stixId, p.id)));

  // 2. Telemetry layer: a revoked data component, and every relationship to it, is no telemetry evidence
  const allDataComponents = await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_DATA_COMPONENT], {
    baseData: true,
    baseFields: ['name', 'revoked', ...EVIDENCE_ACCESS_FIELDS],
  });
  const { dataComponents, detects, provides } = withoutRevokedDataComponents(
    allDataComponents,
    await loadRelationsToTechniques(context, user, RELATION_DETECTS, [ENTITY_TYPE_DATA_COMPONENT], scopedIds),
    await fullRelationsList<BasicStoreRelation>(context, user, RELATION_PROVIDES, {
      toTypes: [ENTITY_TYPE_DATA_COMPONENT],
      baseData: true,
      baseFields: EVIDENCE_ACCESS_FIELDS,
    }),
  );
  const dataComponentIdsByName = new Map<string, string[]>();
  dataComponents.forEach((dc) => {
    const key = (dc.name ?? '').trim().toLowerCase();
    dataComponentIdsByName.set(key, [...(dataComponentIdsByName.get(key) ?? []), dc.internal_id]);
  });
  const mappings = (await listAllDefenseLogsourceMappings(context, user)).filter((m) => m.active);

  // 3. Detection layer: rule indicators
  const indicates = await loadRelationsToTechniques(context, user, RELATION_INDICATES, [ENTITY_TYPE_INDICATOR], scopedIds);
  const indicators = await findByIdsChunked<BasicStoreEntityIndicator>(context, user, indicates.map((i) => i.fromId), {
    type: ENTITY_TYPE_INDICATOR,
    baseData: true,
    baseFields: INDICATOR_BASE_FIELDS,
  });
  const rules = indicators.filter((i) => !i.revoked && DEFENSE_RULE_PATTERN_TYPES.includes((i.pattern_type ?? '').toLowerCase()));
  const rulesById = new Map(rules.map((r) => [r.internal_id, r]));

  // 4. Mitigation and validation layers
  const allMitigates = await loadRelationsToTechniques(context, user, RELATION_MITIGATES, [ENTITY_TYPE_COURSE_OF_ACTION], scopedIds);
  const coursesOfAction = await findByIdsChunked<BasicStoreEntity>(context, user, allMitigates.map((m) => m.fromId), {
    type: ENTITY_TYPE_COURSE_OF_ACTION,
    baseData: true,
    baseFields: ['revoked'],
  });
  const mitigates = activeMitigations(allMitigates, coursesOfAction);
  const allHasCovered = await loadRelationsToTechniques(context, user, RELATION_HAS_COVERED, [ENTITY_TYPE_SECURITY_COVERAGE_RESULT], scopedIds, [
    'coverage_information',
    'coverage_platforms_information',
    'updated_at',
  ]);
  const allResults = await findByIdsChunked<BasicStoreEntity>(context, user, allHasCovered.map((h) => h.fromId), { type: ENTITY_TYPE_SECURITY_COVERAGE_RESULT });
  const results = currentCoverageResults(allResults, computedAt);
  const resultIds = new Set(results.map((r) => r.internal_id));
  const hasCovered = allHasCovered.filter((h) => resultIds.has(h.fromId));

  const graph: ComputationGraph = {
    platforms,
    platformIdByStixId,
    detectsByTechnique: groupBy(detects, (r) => r.toId),
    providesByDataComponent: groupBy(provides, (r) => r.toId),
    indicatesByTechnique: groupBy(indicates, (r) => r.toId),
    rulesById,
    mitigatesByTechnique: groupBy(mitigates, (r) => r.toId),
    hasCoveredByTechnique: groupBy(hasCovered, (r) => r.toId),
    resultsById: new Map(results.map((r) => [r.internal_id, r])),
    dataComponentIdsByName,
    mappings,
    accessKeyById: buildAccessKeys([...detects, ...provides, ...dataComponents, ...indicates, ...rules, ...mitigates, ...hasCovered, ...results]),
  };

  // 5. Vectors, written only when they changed
  const entries: Array<{ attackPattern: BasicStoreEntity; coverage: DefenseCoverage }> = [];
  const updates: Array<{ attackPattern: BasicStoreEntity; coverage: DefenseCoverage }> = [];
  for (let index = 0; index < activeAttackPatterns.length; index += 1) {
    await doYield();
    const attackPattern = activeAttackPatterns[index];
    const coverage = buildTechniqueCoverage(attackPattern.internal_id, graph, computedAt);
    entries.push({ attackPattern, coverage });
    const previous = (attackPattern as unknown as { x_opencti_defense_coverage?: DefenseCoverage }).x_opencti_defense_coverage;
    if (coverageSignature(previous) !== coverageSignature(coverage)) {
      updates.push({ attackPattern, coverage });
    }
  }
  // The level changes are queued before the new coverage is stored: once stored, it is their baseline and a computation
  // retried after a failure would not find them again
  const coverageChanges = collectDefenseCoverageChanges(updates.map(({ attackPattern, coverage }) => ({
    attackPatternId: attackPattern.internal_id,
    previous: (attackPattern as unknown as { x_opencti_defense_coverage?: DefenseCoverage }).x_opencti_defense_coverage,
    coverage,
  })));
  await queuePendingLevelChanges(coverageChanges);
  await bulkUpdateCoverages(context, updates);
  const cleared = await clearRevokedCoverages(context, revokedAttackPatterns);

  // 6. Gap lifecycle records
  const platformKeys = [DEFENSE_AGGREGATE_PLATFORM, ...platforms.map((p) => p.id)];
  const { gaps, written, closed } = await storeGaps(context, user, entries, platformKeys, platforms, computedAt);
  if (isFull) {
    await deleteStaleGaps(context, user, new Set(techniqueIds), new Set(platformKeys), computedAt);
  } else {
    await deleteGapsOfTechniques(revokedIds);
  }
  await bumpDefenseCoverageVersion();
  // 7. Live triggers on the queued level changes, once the new coverage is readable; a failed delivery is retried from
  // the queue by the next run
  let notified = 0;
  try {
    notified = await deliverPendingDefenseLevelChanges(context);
  } catch (error) {
    logApp.error('[DEFENSE-COVERAGE] Queued defense level changes could not be delivered', { cause: error });
  }
  const result = {
    techniques: activeAttackPatterns.length,
    updated: updates.length,
    cleared,
    level_changes: coverageChanges.filter((change) => change.previous.level !== change.coverage.level).length,
    notified,
    gaps,
    written_gaps: written,
    closed_gaps: closed,
    platforms: platforms.length,
    duration: Date.now() - start,
  };
  logApp.info(`[DEFENSE-COVERAGE] ${isFull ? 'Full' : 'Incremental'} computation done`, result);
  return result;
};

/**
 * Techniques impacted by a change on some data components (detects them) or rule indicators (indicate them).
 */
export const findTechniquesOfSources = async (context: AuthContext, user: AuthUser, relationshipType: string, sourceIds: string[]) => {
  if (sourceIds.length === 0) return [];
  const techniques: string[] = [];
  const chunks = chunkIds(R.uniq(sourceIds));
  for (let index = 0; index < chunks.length; index += 1) {
    const relations = await fullRelationsList<BasicStoreRelation>(context, user, relationshipType, {
      fromId: chunks[index],
      toTypes: [ENTITY_TYPE_ATTACK_PATTERN],
      baseData: true,
    });
    techniques.push(...relations.map((r) => r.toId));
  }
  return R.uniq(techniques);
};

/**
 * Kill chain phases (tactics) of the techniques, for the coverage per tactic.
 */
export const loadKillChainPhases = async (context: AuthContext, user: AuthUser) => {
  return fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_KILL_CHAIN_PHASE], {
    indices: [READ_INDEX_STIX_META_OBJECTS],
    filters: { mode: FilterMode.And, filters: [], filterGroups: [] },
  });
};

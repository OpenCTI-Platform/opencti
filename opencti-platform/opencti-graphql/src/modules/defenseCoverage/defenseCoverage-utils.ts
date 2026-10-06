import {
  DEFENSE_AGGREGATE_PLATFORM,
  DEFENSE_DEPLOYMENT_STATUS_ACTIVE,
  DEFENSE_DETECTION_ORDER,
  DEFENSE_LEVEL_DETECTION_AVAILABLE,
  DEFENSE_LEVEL_DETECTION_DEPLOYED,
  DEFENSE_LEVEL_NONE,
  DEFENSE_LIVE_DEPLOYMENT_STATUSES,
  DEFENSE_LEVEL_TELEMETRY,
  DEFENSE_LEVEL_VALIDATED,
  DEFENSE_VALIDATION_ORDER,
  type DefenseCell,
  type DefenseCellPlatform,
  type DefenseCoverage,
  type DefenseDeploymentEvidence,
  type DefenseDetectionStatus,
  type DefenseEvidence,
  type DefensePlatformVector,
  type DefenseRecommendedAction,
  type DefenseScore,
  type DefenseTelemetryEvidence,
  type DefenseThreatUsage,
  type DefenseValidationEvidence,
  type DefenseValidationStatus,
} from './defenseCoverage-types';

export type AccessPredicate = (id: string | undefined) => boolean;

const COVERAGE_DETECTION = 'detection';
const COVERAGE_PREVENTION = 'prevention';

// region validation
/**
 * Validation status of one OpenAEV result for a technique.
 * - prevented: the prevention success rate reaches the threshold,
 * - detected: the detection success rate reaches the threshold,
 * - failed: detection or prevention was tested but stays under the threshold,
 * - none: nothing attributable to detection or prevention (vulnerability only, empty result).
 */
export const computeValidationStatus = (scores: DefenseScore[], threshold: number): DefenseValidationStatus => {
  const normalized = scores.map((s) => ({ name: (s.name ?? '').toLowerCase(), score: Number(s.score ?? 0) }));
  const prevention = normalized.filter((s) => s.name === COVERAGE_PREVENTION);
  const detection = normalized.filter((s) => s.name === COVERAGE_DETECTION);
  if (prevention.some((s) => s.score >= threshold)) {
    return 'prevented';
  }
  if (detection.some((s) => s.score >= threshold)) {
    return 'detected';
  }
  if (prevention.length > 0 || detection.length > 0) {
    return 'failed';
  }
  return 'none';
};

const resultTime = (validation: DefenseValidationEvidence) => {
  return validation.last_result_at ? new Date(validation.last_result_at).getTime() : 0;
};

/**
 * The latest result is the current truth. When several results share the same date, the best one wins.
 */
export const latestValidation = (validations: DefenseValidationEvidence[]): DefenseValidationEvidence | undefined => {
  const meaningful = validations.filter((v) => v.status !== 'none');
  if (meaningful.length === 0) {
    return undefined;
  }
  return [...meaningful].sort((a, b) => {
    const timeDiff = resultTime(b) - resultTime(a);
    if (timeDiff !== 0) return timeDiff;
    return DEFENSE_VALIDATION_ORDER[b.status] - DEFENSE_VALIDATION_ORDER[a.status];
  })[0];
};

export const isValidationSuccess = (status: DefenseValidationStatus) => status === 'prevented' || status === 'detected';
// endregion

// region detection
export const computeDetectionStatus = (deployments: DefenseDeploymentEvidence[], hasAvailableRule: boolean): DefenseDetectionStatus => {
  if (deployments.some((d) => d.status === DEFENSE_DEPLOYMENT_STATUS_ACTIVE)) {
    return 'active';
  }
  if (deployments.some((d) => DEFENSE_LIVE_DEPLOYMENT_STATUSES.includes(d.status))) {
    return 'deployed';
  }
  return hasAvailableRule ? 'available' : 'none';
};

export const maxDetectionStatus = (statuses: DefenseDetectionStatus[]): DefenseDetectionStatus => {
  return statuses.reduce<DefenseDetectionStatus>((best, current) => {
    return DEFENSE_DETECTION_ORDER[current] > DEFENSE_DETECTION_ORDER[best] ? current : best;
  }, 'none');
};
// endregion

// region levels
/**
 * Level of a technique on one security platform:
 * 1 the platform collects a data component detecting the technique,
 * 2 a detection rule indicating the technique is available in OpenCTI (deployment unknown),
 * 3 a rule indicating the technique is deployed (or active) on the platform,
 * 4 OpenAEV proved the detection or the prevention on the platform.
 * A failed latest validation caps the level at 2: the deployed detection is proven ineffective.
 */
export const computePlatformLevel = (telemetry: boolean, detection: DefenseDetectionStatus, validated: DefenseValidationStatus): number => {
  let level = DEFENSE_LEVEL_NONE;
  if (telemetry) {
    level = DEFENSE_LEVEL_TELEMETRY;
  }
  if (detection === 'available') {
    level = DEFENSE_LEVEL_DETECTION_AVAILABLE;
  }
  if (detection === 'deployed' || detection === 'active') {
    level = DEFENSE_LEVEL_DETECTION_DEPLOYED;
  }
  if (isValidationSuccess(validated)) {
    level = DEFENSE_LEVEL_VALIDATED;
  }
  if (validated === 'failed') {
    level = Math.min(level, DEFENSE_LEVEL_DETECTION_AVAILABLE);
  }
  return level;
};

/**
 * Aggregated level of a technique over a set of platforms: the best platform level, raised to
 * 1 when any platform collects telemetry, to 2 when a rule is available in OpenCTI, and to 4 when
 * an OpenAEV result not attributed to a platform proves the detection or the prevention.
 */
export const computeAggregateLevel = (
  platformLevels: number[],
  telemetry: boolean,
  hasAvailableRule: boolean,
  unattributedValidation: DefenseValidationStatus,
): number => {
  let baseline = DEFENSE_LEVEL_NONE;
  if (telemetry) baseline = DEFENSE_LEVEL_TELEMETRY;
  if (hasAvailableRule) baseline = DEFENSE_LEVEL_DETECTION_AVAILABLE;
  if (isValidationSuccess(unattributedValidation)) baseline = DEFENSE_LEVEL_VALIDATED;
  return Math.max(baseline, ...platformLevels);
};

export const computeRecommendedAction = (input: {
  level: number;
  telemetry: boolean;
  detection: DefenseDetectionStatus;
  validated: DefenseValidationStatus;
  hasDetectingDataComponent: boolean;
}): DefenseRecommendedAction => {
  const { level, telemetry, detection, validated, hasDetectingDataComponent } = input;
  if (level >= DEFENSE_LEVEL_VALIDATED) return 'none';
  if (validated === 'failed') return 'fix_detection';
  if (detection === 'deployed') return 'activate_rule';
  if (detection === 'active') return 'validate';
  if (!telemetry && hasDetectingDataComponent) return 'add_telemetry';
  if (detection === 'available') return telemetry ? 'deploy_rule' : 'add_telemetry';
  return 'import_rule';
};
// endregion

// region evidences
/**
 * Bounds an evidence list. Levels are evaluated per reader after access filtering, so when an access key is given
 * every access partition keeps its first evidence whatever the bound (the bound only applies to the others, taken
 * round robin): a reader who can see any evidence of a partition still sees one. The level class splits a partition
 * where the evidence kind matters to the level (the deployment status), so that each class stays represented too.
 * Pass the evidences in preference order: the first one of a partition is the one kept.
 * The partitions themselves are bounded by maxPartitions, a hard limit on how far the stored size may exceed the
 * evidence bound: beyond it, the partitions of the first evidences in preference order are kept, so a reader of a
 * dropped partition may see a lower level, never a higher one. A limit below the evidence bound does not lower the
 * number of partitions kept: up to the evidence bound the stored size is already bounded by `max`, and each partition
 * kept is one more reader who still sees an evidence.
 */
export const capEvidences = <T>(
  evidences: T[],
  max: number,
  accessKeyOf?: (evidence: T) => string,
  levelClassOf?: (evidence: T) => string,
  maxPartitions = max * 4,
): T[] => {
  if (evidences.length <= max) return evidences;
  if (!accessKeyOf) return evidences.slice(0, max);
  const groups = new Map<string, T[]>();
  evidences.forEach((evidence) => {
    const key = levelClassOf ? `${accessKeyOf(evidence)}|${levelClassOf(evidence)}` : accessKeyOf(evidence);
    const group = groups.get(key);
    if (group) group.push(evidence);
    else groups.set(key, [evidence]);
  });
  const groupLists = Array.from(groups.values()).slice(0, Math.max(max, maxPartitions));
  const capped: T[] = groupLists.map((group) => group[0]);
  for (let round = 1; capped.length < max; round += 1) {
    const picks = groupLists.filter((group) => round < group.length).map((group) => group[round]);
    if (picks.length === 0) break;
    capped.push(...picks.slice(0, max - capped.length));
  }
  return capped;
};

const uniq = (values: string[]) => Array.from(new Set(values));

const isEvidenceAccessible = (evidence: DefenseEvidence, can: AccessPredicate) => can(evidence.id) && can(evidence.rel);

// An inferred telemetry derives from a deployed rule and the indicates relationship that links it to
// the technique: the reader needs access to both, as for the deployment itself
const isTelemetryAccessible = (evidence: DefenseTelemetryEvidence, can: AccessPredicate) => {
  if (!isEvidenceAccessible(evidence, can) || !can(evidence.detects)) return false;
  if (!evidence.inferred_from) return true;
  return !!evidence.indicates && can(evidence.inferred_from) && can(evidence.indicates);
};

const isDeploymentAccessible = (evidence: DefenseDeploymentEvidence, can: AccessPredicate) => {
  return isEvidenceAccessible(evidence, can) && can(evidence.indicates);
};

export interface DefenseValidationTarget {
  attackPatternId: string;
  platformId: string;
}

/**
 * The gaps a validation request is tracked on: the aggregate gap of every technique, every technique on
 * every requested platform, and the exact technique and platform pairs selected in the gap backlog (a pair
 * never extends to the other techniques or platforms of the selection).
 */
export const buildValidationTargets = (
  attackPatternIds: ReadonlyArray<string>,
  platformIds: ReadonlyArray<string>,
  gaps: ReadonlyArray<DefenseValidationTarget>,
): DefenseValidationTarget[] => {
  const targets = new Map<string, DefenseValidationTarget>();
  const add = (attackPatternId: string, platformId: string) => {
    targets.set(`${attackPatternId}|${platformId}`, { attackPatternId, platformId });
  };
  attackPatternIds.forEach((attackPatternId) => {
    add(attackPatternId, DEFENSE_AGGREGATE_PLATFORM);
    platformIds.forEach((platformId) => add(attackPatternId, platformId));
  });
  gaps.forEach((gap) => add(gap.attackPatternId, gap.platformId));
  return Array.from(targets.values());
};

/**
 * Parent technique of a sub-technique as a reader may see it: only when he can access both the parent
 * and the subtechnique-of relationship that links them.
 */
export const visibleParentId = (technique: { parent_id?: string; parent_rel_id?: string }, can: AccessPredicate) => {
  if (!technique.parent_id || !technique.parent_rel_id) return undefined;
  return can(technique.parent_id) && can(technique.parent_rel_id) ? technique.parent_id : undefined;
};

/**
 * All the ids a reader must be allowed to access for every evidence of a stored coverage.
 */
export const collectCoverageIds = (coverage: DefenseCoverage | undefined): string[] => {
  if (!coverage) return [];
  const ids: string[] = [];
  const pushEvidence = (e: DefenseEvidence) => {
    ids.push(e.id, e.rel);
  };
  (coverage.data_components ?? []).forEach(pushEvidence);
  (coverage.rules ?? []).forEach(pushEvidence);
  (coverage.mitigations ?? []).forEach(pushEvidence);
  (coverage.validations ?? []).forEach(pushEvidence);
  (coverage.platforms ?? []).forEach((p) => {
    ids.push(p.platform_id);
    p.telemetry.forEach((t) => {
      pushEvidence(t);
      ids.push(t.detects);
      if (t.inferred_from) ids.push(t.inferred_from);
      if (t.indicates) ids.push(t.indicates);
    });
    p.deployments.forEach((d) => {
      pushEvidence(d);
      ids.push(d.indicates);
    });
    p.validations.forEach(pushEvidence);
  });
  return uniq(ids.filter((id) => !!id));
};

const evaluatePlatform = (
  vector: DefensePlatformVector,
  can: AccessPredicate,
  accessibleRuleIds: string[],
  hasDetectingDataComponent: boolean,
): DefenseCellPlatform => {
  const telemetryEvidences = vector.telemetry.filter((t) => isTelemetryAccessible(t, can));
  const deployments = vector.deployments.filter((d) => isDeploymentAccessible(d, can));
  const validations = vector.validations.filter((v) => isEvidenceAccessible(v, can));
  const telemetry = telemetryEvidences.length > 0;
  const detection = computeDetectionStatus(deployments, accessibleRuleIds.length > 0);
  const latest = latestValidation(validations);
  const validated = latest?.status ?? 'none';
  const level = computePlatformLevel(telemetry, detection, validated);
  return {
    platform_id: vector.platform_id,
    telemetry,
    detection,
    validated,
    last_result_at: latest?.last_result_at,
    level,
    data_component_ids: uniq(telemetryEvidences.filter((t) => !t.inferred_from).map((t) => t.id)),
    inferred_data_component_ids: uniq(telemetryEvidences.filter((t) => !!t.inferred_from).map((t) => t.id)),
    rule_ids: uniq(deployments.map((d) => d.id)),
    coverage_result_ids: uniq(validations.map((v) => v.id)),
    recommended_action: computeRecommendedAction({ level, telemetry, detection, validated, hasDetectingDataComponent }),
  };
};

/**
 * Evaluate a stored coverage for one reader.
 * Only the evidences the reader can access are kept, then every status and level is recomputed from them,
 * so a cell never reflects a rule, a data component or a result the reader is not allowed to see.
 *
 * @param attackPatternId the technique
 * @param coverage the stored coverage (computed by the manager)
 * @param can access predicate on element and relationship ids
 * @param platformIds selected platforms, undefined for every platform
 */
export const evaluateCoverage = (
  attackPatternId: string,
  coverage: DefenseCoverage | undefined,
  can: AccessPredicate,
  platformIds?: string[],
): DefenseCell => {
  const dataComponents = (coverage?.data_components ?? []).filter((e) => isEvidenceAccessible(e, can));
  const rules = (coverage?.rules ?? []).filter((e) => isEvidenceAccessible(e, can));
  const mitigations = (coverage?.mitigations ?? []).filter((e) => isEvidenceAccessible(e, can));
  const ruleIds = uniq(rules.map((r) => r.id));
  const hasDetectingDataComponent = dataComponents.length > 0;
  const selectedVectors = (coverage?.platforms ?? [])
    .filter((p) => can(p.platform_id))
    .filter((p) => !platformIds || platformIds.includes(p.platform_id));
  const platforms = selectedVectors.map((vector) => evaluatePlatform(vector, can, ruleIds, hasDetectingDataComponent));
  // Results not attributed to a platform only count when no platform is selected
  // The stored flag survives the cap of the platform lists, the vectors only tell for coverages stored without it
  const attributedIds = new Set((coverage?.platforms ?? []).flatMap((p) => p.validations.map((v) => v.rel)));
  const unattributed = !platformIds
    ? (coverage?.validations ?? []).filter((v) => !(v.attributed ?? attributedIds.has(v.rel)) && isEvidenceAccessible(v, can))
    : [];
  const unattributedLatest = latestValidation(unattributed);
  const platformValidations = platforms.filter((p) => p.validated !== 'none').map((p) => ({
    id: p.platform_id,
    rel: p.platform_id,
    status: p.validated,
    last_result_at: p.last_result_at,
    scores: [],
  } as DefenseValidationEvidence));
  const latest = latestValidation([...platformValidations, ...(unattributedLatest ? [unattributedLatest] : [])]);
  const telemetry = platforms.some((p) => p.telemetry);
  const detection = maxDetectionStatus([...platforms.map((p) => p.detection), ruleIds.length > 0 ? 'available' : 'none']);
  const validated = latest?.status ?? 'none';
  const aggregateLevel = computeAggregateLevel(platforms.map((p) => p.level), telemetry, ruleIds.length > 0, unattributedLatest?.status ?? 'none');
  // The latest failure caps the technique, unless a platform still holds its own successful validation
  const level = validated === 'failed' && !platforms.some((p) => p.level >= DEFENSE_LEVEL_VALIDATED)
    ? Math.min(aggregateLevel, DEFENSE_LEVEL_DETECTION_AVAILABLE)
    : aggregateLevel;
  const coverageResultIds = uniq([
    ...platforms.flatMap((p) => p.coverage_result_ids),
    ...unattributed.map((v) => v.id),
  ]);
  return {
    attack_pattern_id: attackPatternId,
    level,
    telemetry,
    detection,
    validated,
    last_result_at: latest?.last_result_at,
    mitigated: mitigations.length > 0,
    data_component_ids: uniq(dataComponents.map((d) => d.id)),
    rule_ids: ruleIds,
    mitigation_ids: uniq(mitigations.map((m) => m.id)),
    coverage_result_ids: coverageResultIds,
    platforms,
    recommended_action: computeRecommendedAction({ level, telemetry, detection, validated, hasDetectingDataComponent }),
    computed_at: coverage?.computed_at,
  };
};

/**
 * What the platforms of a gap row provide and deploy. The aggregated cell holds every detecting data component and
 * every rule, so the row of all platforms counts what any of its platforms provides or deploys instead.
 */
export const gapPlatformEvidence = (cell: DefenseCell, platformId: string) => {
  const cells = platformId === DEFENSE_AGGREGATE_PLATFORM ? cell.platforms : [cellForPlatform(cell, platformId)];
  return {
    data_component_ids: uniq(cells.flatMap((p) => [...p.data_component_ids, ...p.inferred_data_component_ids])),
    rule_ids: uniq(cells.flatMap((p) => p.rule_ids)),
  };
};

/**
 * The cell of one platform, or the aggregated cell when no platform is given.
 */
export const cellForPlatform = (cell: DefenseCell, platformId: string) => {
  if (platformId === DEFENSE_AGGREGATE_PLATFORM) {
    return {
      platform_id: DEFENSE_AGGREGATE_PLATFORM,
      telemetry: cell.telemetry,
      detection: cell.detection,
      validated: cell.validated,
      last_result_at: cell.last_result_at,
      level: cell.level,
      data_component_ids: cell.data_component_ids,
      inferred_data_component_ids: [],
      rule_ids: cell.rule_ids,
      coverage_result_ids: cell.coverage_result_ids,
      recommended_action: cell.recommended_action,
    } as DefenseCellPlatform;
  }
  const found = cell.platforms.find((p) => p.platform_id === platformId);
  if (found) {
    return found;
  }
  const detection: DefenseDetectionStatus = cell.rule_ids.length > 0 ? 'available' : 'none';
  const level = computePlatformLevel(false, detection, 'none');
  return {
    platform_id: platformId,
    telemetry: false,
    detection,
    validated: 'none',
    level,
    data_component_ids: [],
    inferred_data_component_ids: [],
    rule_ids: [],
    coverage_result_ids: [],
    recommended_action: computeRecommendedAction({
      level,
      telemetry: false,
      detection,
      validated: 'none',
      hasDetectingDataComponent: cell.data_component_ids.length > 0,
    }),
  } as DefenseCellPlatform;
};
// endregion

/**
 * Techniques as counted by the matrix totals, by id: a parent technique carries the best level and the threat usage
 * of its sub-techniques, and a sub-technique whose parent is not among the cells (revoked, or not accessible to the
 * reader) counts on its own.
 */
export const countEffectiveTechniques = (
  cells: ReadonlyArray<{ attack_pattern_id: string; parent_attack_pattern_id?: string; level: number; threats_count: number }>,
): Map<string, { level: number; used: boolean }> => {
  const ids = new Set(cells.map((c) => c.attack_pattern_id));
  const isCountedAlone = (cell: { parent_attack_pattern_id?: string }) => !cell.parent_attack_pattern_id || !ids.has(cell.parent_attack_pattern_id);
  const effective = new Map<string, { level: number; used: boolean }>();
  cells.filter(isCountedAlone).forEach((c) => effective.set(c.attack_pattern_id, { level: c.level, used: c.threats_count > 0 }));
  cells.filter((c) => !isCountedAlone(c)).forEach((sub) => {
    const parent = effective.get(sub.parent_attack_pattern_id as string);
    if (parent) {
      parent.level = Math.max(parent.level, sub.level);
      parent.used = parent.used || sub.threats_count > 0;
    }
  });
  return effective;
};

// region threats and priority
const MIN_THREAT_CONFIDENCE_WEIGHT = 0.1;

/**
 * Threat weight of a technique: one point per threat using it, weighted by the confidence of its
 * strongest uses relationship (minimum 10% so every visible usage counts).
 */
export const computeThreatWeight = (usages: DefenseThreatUsage[]): number => {
  const bestByThreat = new Map<string, number>();
  usages.forEach((usage) => {
    const weight = Math.max(MIN_THREAT_CONFIDENCE_WEIGHT, Math.min(1, (usage.confidence ?? 0) / 100));
    bestByThreat.set(usage.threat_id, Math.max(bestByThreat.get(usage.threat_id) ?? 0, weight));
  });
  const total = Array.from(bestByThreat.values()).reduce((sum, w) => sum + w, 0);
  return Math.round(total * 100) / 100;
};

/**
 * Priority (0-100) = gap severity x threat relevance.
 * Gap severity: (4 - level) / 4. Threat relevance: 0.1 without any threat, tending to 1 when several
 * confident threats use the technique (1 - e^(-weight / 2)).
 */
export const computeGapPriority = (level: number, threatWeight: number): number => {
  const severity = Math.max(0, DEFENSE_LEVEL_VALIDATED - level) / DEFENSE_LEVEL_VALIDATED;
  const relevance = 0.1 + 0.9 * (1 - Math.exp(-Math.max(0, threatWeight) / 2));
  return Math.round(severity * relevance * 100);
};
// endregion

// region logsource mapping
export interface LogsourceCondition {
  x_opencti_rule_logsource?: Logsource | null;
  data_components: string[];
  active?: boolean;
}

export interface Logsource {
  category?: string | null;
  product?: string | null;
  service?: string | null;
}

const norm = (value: string | null | undefined) => (value ?? '').trim().toLowerCase();

export const buildLogsourceMappingKey = (category?: string | null, product?: string | null, service?: string | null) => {
  return `${norm(category)}|${norm(product)}|${norm(service)}`;
};

/**
 * A mapping entry matches a log source when every field set on the entry equals the log source field.
 * Entries without any field never match.
 */
export const isLogsourceMatching = (entry: LogsourceCondition, logsource: Logsource) => {
  const expected = entry.x_opencti_rule_logsource ?? {};
  const conditions: Array<[string, string]> = [
    [norm(expected.category), norm(logsource.category)],
    [norm(expected.product), norm(logsource.product)],
    [norm(expected.service), norm(logsource.service)],
  ];
  const defined = conditions.filter(([expected]) => expected.length > 0);
  return defined.length > 0 && defined.every(([expected, actual]) => expected === actual);
};

/**
 * Data component names required by a log source according to the active mapping entries
 * (deduplicated case-insensitively, first spelling kept).
 */
export const mapLogsourceToDataComponents = (logsource: Logsource | undefined | null, entries: LogsourceCondition[]): string[] => {
  if (!logsource) return [];
  const names = new Map<string, string>();
  entries
    .filter((e) => e.active !== false)
    .filter((e) => isLogsourceMatching(e, logsource))
    .forEach((e) => e.data_components.forEach((dc) => {
      const name = (dc ?? '').trim();
      if (name.length > 0 && !names.has(norm(name))) names.set(norm(name), name);
    }));
  return Array.from(names.values());
};
// endregion

// region rule ranking
const RULE_STATUS_RANK: Record<string, number> = { stable: 5, test: 4, experimental: 3, unsupported: 1, deprecated: 0 };
const RULE_LEVEL_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };

export interface RankableRule {
  id: string;
  x_opencti_rule_status?: string;
  x_opencti_rule_level?: string;
  compatible: boolean; // the platform collects the data components required by the rule log source
}

/**
 * Rule candidates first by compatibility with the platform telemetry, then by maturity and level.
 */
export const rankRuleCandidates = <T extends RankableRule>(rules: T[]): T[] => {
  return [...rules].sort((a, b) => {
    if (a.compatible !== b.compatible) return a.compatible ? -1 : 1;
    const statusDiff = (RULE_STATUS_RANK[b.x_opencti_rule_status ?? ''] ?? 2) - (RULE_STATUS_RANK[a.x_opencti_rule_status ?? ''] ?? 2);
    if (statusDiff !== 0) return statusDiff;
    return (RULE_LEVEL_RANK[b.x_opencti_rule_level ?? ''] ?? 0) - (RULE_LEVEL_RANK[a.x_opencti_rule_level ?? ''] ?? 0);
  });
};
// endregion

// region export
const CSV_FORMULA_PREFIXES = ['=', '+', '-', '@', '\t', '\r'];

/**
 * Escape a CSV value (RFC 4180) and neutralize spreadsheet formulas (CSV injection).
 */
export const escapeCsvValue = (value: unknown): string => {
  if (value === null || value === undefined) return '';
  let str = Array.isArray(value) ? value.join('; ') : String(value);
  if (str.length > 0 && CSV_FORMULA_PREFIXES.includes(str[0])) {
    str = `'${str}`;
  }
  if (/[",\n\r;]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
};

/**
 * Every validation evidence of a technique, once per result and relationship. The technique-wide list and the
 * per-platform lists are capped independently: a result raising the level of a selected platform may only be
 * kept in that platform's list. The technique-wide entry wins when both exist.
 */
export const validationEvidencePool = (coverage: DefenseCoverage | undefined): DefenseValidationEvidence[] => {
  const pool = new Map<string, DefenseValidationEvidence>();
  [...(coverage?.validations ?? []), ...(coverage?.platforms ?? []).flatMap((p) => p.validations)].forEach((v) => {
    const key = `${v.id}|${v.rel}`;
    if (!pool.has(key)) pool.set(key, v);
  });
  return Array.from(pool.values());
};

export const buildCsv = (headers: string[], rows: unknown[][]): string => {
  const lines = [headers.map(escapeCsvValue).join(',')];
  rows.forEach((row) => lines.push(row.map(escapeCsvValue).join(',')));
  return `${lines.join('\r\n')}\r\n`;
};
// endregion

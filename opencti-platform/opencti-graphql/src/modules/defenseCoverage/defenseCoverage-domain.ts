import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../database/middleware-loader';
import { elBulk } from '../../database/engine';
import { buildEntityData } from '../../database/data-builder';
import { FunctionalError } from '../../config/errors';
import { logApp } from '../../config/conf';
import { SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../schema/stixDomainObject';
import { RELATION_PROVIDES } from '../../schema/stixCoreRelationship';
import { addStixCoreRelationship } from '../../domain/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR, type BasicStoreEntityIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { type BasicStoreEntitySecurityCoverage, ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import type { BasicStoreEntityDataComponent } from '../dataComponent/dataComponent-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { addSecurityCoverage } from '../securityCoverage/securityCoverage-domain';
import { addGrouping } from '../grouping/grouping-domain';
import { addDefenseGapExportCount, addDefenseValidationRequestCount } from '../../manager/telemetryManager';
import { INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import type { DefenseGapsFilter, DefenseGapsOrdering, DefenseLogsourceInput, DefenseValidationInput, OrderingMode } from '../../generated/graphql';
import {
  DEFENSE_AGGREGATE_PLATFORM,
  DEFENSE_LEVEL_MAX,
  DEFENSE_LEVEL_VALIDATED,
  DEFENSE_THREAT_TYPES,
  type DefenseCell,
  type DefenseCellPlatform,
  type DefenseCoverage,
  type DefenseDetectionStatus,
  type DefenseRecommendedAction,
  type DefenseScore,
  type DefenseThreatOverlay,
  type DefenseValidationStatus,
} from './defenseCoverage-types';
import {
  type AccessPredicate,
  buildCsv,
  cellForPlatform,
  computeGapPriority,
  computeThreatWeight,
  evaluateCoverage,
  mapLogsourceToDataComponents,
  rankRuleCandidates,
} from './defenseCoverage-utils';
import { type DefensePlatform, defenseGapId, loadDefensePlatforms } from './defenseCoverage-compute';
import { type DefenseSnapshot, type DefenseTechniqueEntry, type DefenseThreatScope, getAccessPredicate, getDefenseSnapshot, getThreatOverlay } from './defenseCoverage-reader';
import { getLastFullComputation, isFullComputationRequested, requestFullDefenseCoverageComputation } from './defenseCoverage-state';
import { listAllDefenseLogsourceMappings } from './defenseLogsourceMapping/defenseLogsourceMapping-domain';
import {
  DEFENSE_GAP_STATUS_CLOSED,
  DEFENSE_GAP_STATUS_OPEN,
  ENTITY_TYPE_DEFENSE_GAP,
  type BasicStoreEntityDefenseGap,
  type DefenseGapValidationRequest,
} from './defenseGap/defenseGap-types';

const DEFAULT_GAPS_PAGE_SIZE = 50;
const MAX_GAPS_PAGE_SIZE = 500;
const MAX_EXPORT_ROWS = 10000;
const MAX_VALIDATION_TECHNIQUES = 200;
const MAX_LOGSOURCES = 200;
const DEFAULT_RULE_CANDIDATES = 5;
const IDS_CHUNK_SIZE = 5000;

// region views
export interface DefensePlatformView {
  id: string;
  name: string;
  entity_type: string;
  security_platform_type?: string;
}

export interface DefenseCellPlatformView {
  platform_id: string;
  level: number;
  telemetry: boolean;
  detection: DefenseDetectionStatus;
  validated: DefenseValidationStatus;
  last_result_at?: string;
  recommended_action: DefenseRecommendedAction;
  data_components_count: number;
  inferred_data_components_count: number;
  rules_count: number;
  results_count: number;
}

export interface DefenseMatrixCellView {
  attack_pattern_id: string;
  x_mitre_id?: string;
  name: string;
  parent_attack_pattern_id?: string;
  kill_chain_phase_ids: string[];
  level: number;
  telemetry: boolean;
  detection: DefenseDetectionStatus;
  validated: DefenseValidationStatus;
  last_result_at?: string;
  mitigated: boolean;
  recommended_action: DefenseRecommendedAction;
  threat_weight: number;
  threats_count: number;
  data_components_count: number;
  rules_count: number;
  mitigations_count: number;
  results_count: number;
  platforms: DefenseCellPlatformView[];
}

export interface DefenseTacticCoverageView {
  kill_chain_phase_id: string;
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
  techniques_count: number;
  levels: number[];
  threat_techniques_count: number;
  threat_levels: number[];
}

export interface DefenseMatrixView {
  computed_at?: string;
  platforms: DefensePlatformView[];
  threats_count: number;
  techniques_count: number;
  levels: number[];
  threat_levels: number[];
  cells: DefenseMatrixCellView[];
  tactics: DefenseTacticCoverageView[];
}

export interface DefenseDataComponentEvidenceView {
  dataComponent: BasicStoreEntity;
  providedBy: DefensePlatformView[];
  inferredBy: DefensePlatformView[];
}

export interface DefenseRuleDeploymentView {
  platform: DefensePlatformView;
  status: string;
}

export interface DefenseRuleEvidenceView {
  indicator: BasicStoreEntityIndicator;
  deployments: DefenseRuleDeploymentView[];
  required_data_components: string[];
}

export interface DefenseCoverageScoreView {
  coverage_name: string;
  coverage_score: number;
}

export interface DefenseValidationPlatformScoreView {
  platform: DefensePlatformView;
  status: DefenseValidationStatus;
  scores: DefenseCoverageScoreView[];
}

export interface DefenseValidationEvidenceView {
  result: BasicStoreEntity;
  securityCoverage: BasicStoreEntity | null;
  status: DefenseValidationStatus;
  last_result_at?: string;
  scores: DefenseCoverageScoreView[];
  platforms: DefenseValidationPlatformScoreView[];
}

export interface DefenseThreatEvidenceView {
  threat: BasicStoreEntity;
  relationship_id: string;
  confidence: number;
}

export interface DefenseProvidesResultView {
  created_count: number;
  dataComponents: BasicStoreEntity[];
  unmatched_data_components: string[];
}

export interface DefenseValidationResultView {
  securityCoverage: BasicStoreEntity;
  grouping: BasicStoreEntity;
  gaps_count: number;
}

interface Evaluation {
  snapshot: DefenseSnapshot;
  can: AccessPredicate;
  platforms: DefensePlatformView[];
  platformById: Map<string, DefensePlatformView>;
  selected?: string[];
  overlay: DefenseThreatOverlay;
}

export interface DefenseTechniqueView {
  attackPattern: BasicStoreEntity;
  computed_at?: string;
  cell: DefenseMatrixCellView;
  evaluated: DefenseCell;
  coverage?: DefenseCoverage;
  technique: DefenseTechniqueEntry;
  evaluation: Evaluation;
}

export interface DefenseGapView {
  id: string;
  internal_id: string;
  standard_id: string;
  entity_type: string;
  parent_types: string[];
  name: string;
  attack_pattern_id: string;
  x_mitre_id?: string;
  attack_pattern_name: string;
  platform_id: string;
  platform: DefensePlatformView | null;
  kill_chain_phase_ids: string[];
  level: number;
  telemetry: boolean;
  detection: DefenseDetectionStatus;
  validated: DefenseValidationStatus;
  last_result_at?: string;
  recommended_action: DefenseRecommendedAction;
  threat_weight: number;
  threats_count: number;
  priority: number;
  status: string;
  opened_at?: string;
  validation_requests: DefenseGapValidationRequest[];
  last_validation_requested_at?: string;
  required_data_component_ids: string[];
  available_rule_ids: string[];
  deployed_rule_ids: string[];
  platform_data_component_ids: string[];
}
// endregion

// region helpers
const uniq = (values: string[]) => Array.from(new Set(values));

const findByIdsChunked = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, ids: string[], opts: Record<string, any> = {}) => {
  const results: T[] = [];
  const chunks = R.splitEvery(IDS_CHUNK_SIZE, uniq(ids));
  for (let index = 0; index < chunks.length; index += 1) {
    const found = await internalFindByIds<T>(context, user, chunks[index], opts) as T[];
    results.push(...found);
  }
  return results;
};

const toPlatformView = (platform: DefensePlatform): DefensePlatformView => ({
  id: platform.id,
  name: platform.name,
  entity_type: platform.entity_type,
  security_platform_type: platform.security_platform_type,
});

export const findDefensePlatforms = async (context: AuthContext, user: AuthUser) => {
  const platforms = await loadDefensePlatforms(context, user);
  return platforms.map(toPlatformView);
};

const prepareEvaluation = async (
  context: AuthContext,
  user: AuthUser,
  platformIds: ReadonlyArray<string> | null | undefined,
  threatScope: DefenseThreatScope | null | undefined,
): Promise<Evaluation> => {
  const snapshot = await getDefenseSnapshot(context);
  const [can, platforms, overlay] = await Promise.all([
    getAccessPredicate(context, user, snapshot),
    findDefensePlatforms(context, user),
    getThreatOverlay(context, user, threatScope),
  ]);
  const platformById = new Map(platforms.map((p) => [p.id, p]));
  const selected = platformIds && platformIds.length > 0 ? platformIds.filter((id) => platformById.has(id)) : undefined;
  return { snapshot, can, platforms, platformById, selected, overlay };
};

const toCellPlatformView = (platform: DefenseCellPlatform): DefenseCellPlatformView => ({
  platform_id: platform.platform_id,
  level: platform.level,
  telemetry: platform.telemetry,
  detection: platform.detection,
  validated: platform.validated,
  last_result_at: platform.last_result_at,
  recommended_action: platform.recommended_action,
  data_components_count: platform.data_component_ids.length,
  inferred_data_components_count: platform.inferred_data_component_ids.length,
  rules_count: platform.rule_ids.length,
  results_count: platform.coverage_result_ids.length,
});

const threatFigures = (overlay: DefenseThreatOverlay, attackPatternId: string) => {
  const usages = overlay.usages.get(attackPatternId) ?? [];
  return { threat_weight: computeThreatWeight(usages), threats_count: uniq(usages.map((u) => u.threat_id)).length };
};

const toCellView = (technique: DefenseTechniqueEntry, cell: DefenseCell, overlay: DefenseThreatOverlay): DefenseMatrixCellView => ({
  attack_pattern_id: technique.id,
  x_mitre_id: technique.x_mitre_id,
  name: technique.name,
  parent_attack_pattern_id: technique.parent_id,
  kill_chain_phase_ids: technique.kill_chain_phase_ids,
  level: cell.level,
  telemetry: cell.telemetry,
  detection: cell.detection,
  validated: cell.validated,
  last_result_at: cell.last_result_at,
  mitigated: cell.mitigated,
  recommended_action: cell.recommended_action,
  ...threatFigures(overlay, technique.id),
  data_components_count: cell.data_component_ids.length,
  rules_count: cell.rule_ids.length,
  mitigations_count: cell.mitigation_ids.length,
  results_count: cell.coverage_result_ids.length,
  platforms: cell.platforms.map(toCellPlatformView),
});

const emptyLevels = () => new Array(DEFENSE_LEVEL_MAX + 1).fill(0) as number[];

const computedAtOf = (snapshot: DefenseSnapshot) => (snapshot.version === 'none' ? undefined : snapshot.version);
// endregion

// region matrix
export const buildDefenseMatrix = async (
  context: AuthContext,
  user: AuthUser,
  args: { platformIds?: ReadonlyArray<string> | null; threatScope?: DefenseThreatScope | null },
): Promise<DefenseMatrixView> => {
  const evaluation = await prepareEvaluation(context, user, args.platformIds, args.threatScope);
  const { snapshot, can, overlay, selected } = evaluation;
  const techniques = snapshot.techniques.filter((t) => can(t.id));
  const cells = techniques.map((technique) => toCellView(technique, evaluateCoverage(technique.id, technique.coverage, can, selected), overlay));
  // Parent techniques carry the best level and the threat usage of their sub-techniques
  const cellsById = new Map(cells.map((c) => [c.attack_pattern_id, c]));
  const effective = new Map<string, { level: number; used: boolean }>();
  cells.filter((c) => !c.parent_attack_pattern_id).forEach((c) => effective.set(c.attack_pattern_id, { level: c.level, used: c.threats_count > 0 }));
  cells.filter((c) => !!c.parent_attack_pattern_id).forEach((sub) => {
    const parent = effective.get(sub.parent_attack_pattern_id as string);
    if (parent) {
      parent.level = Math.max(parent.level, sub.level);
      parent.used = parent.used || sub.threats_count > 0;
    }
  });
  const levels = emptyLevels();
  const threatLevels = emptyLevels();
  effective.forEach((value) => {
    levels[value.level] += 1;
    if (value.used) threatLevels[value.level] += 1;
  });
  const tactics = snapshot.phases.map((phase) => {
    const phaseLevels = emptyLevels();
    const phaseThreatLevels = emptyLevels();
    let count = 0;
    let threatCount = 0;
    effective.forEach((value, id) => {
      const cell = cellsById.get(id);
      if (!cell?.kill_chain_phase_ids.includes(phase.id)) return;
      count += 1;
      phaseLevels[value.level] += 1;
      if (value.used) {
        threatCount += 1;
        phaseThreatLevels[value.level] += 1;
      }
    });
    return {
      kill_chain_phase_id: phase.id,
      kill_chain_name: phase.kill_chain_name,
      phase_name: phase.phase_name,
      x_opencti_order: phase.x_opencti_order,
      techniques_count: count,
      levels: phaseLevels,
      threat_techniques_count: threatCount,
      threat_levels: phaseThreatLevels,
    };
  }).filter((t) => t.techniques_count > 0).sort((a, b) => a.x_opencti_order - b.x_opencti_order);
  return {
    computed_at: computedAtOf(snapshot),
    platforms: evaluation.platforms,
    threats_count: overlay.threats_count,
    techniques_count: effective.size,
    levels,
    threat_levels: threatLevels,
    cells,
    tactics,
  };
};
// endregion

// region technique
export const findDefenseTechnique = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  args: { platformIds?: ReadonlyArray<string> | null; threatScope?: DefenseThreatScope | null },
): Promise<DefenseTechniqueView | null> => {
  const attackPattern = await storeLoadById<BasicStoreEntity>(context, user, id, ENTITY_TYPE_ATTACK_PATTERN);
  if (!attackPattern) {
    return null;
  }
  const evaluation = await prepareEvaluation(context, user, args.platformIds, args.threatScope);
  const stored = evaluation.snapshot.techniquesById.get(attackPattern.internal_id);
  const technique: DefenseTechniqueEntry = stored ?? {
    id: attackPattern.internal_id,
    name: attackPattern.name,
    x_mitre_id: (attackPattern as unknown as { x_mitre_id?: string }).x_mitre_id,
    kill_chain_phase_ids: [],
  };
  const evaluated = evaluateCoverage(technique.id, technique.coverage, evaluation.can, evaluation.selected);
  return {
    attackPattern,
    computed_at: technique.coverage?.computed_at,
    cell: toCellView(technique, evaluated, evaluation.overlay),
    evaluated,
    coverage: technique.coverage,
    technique,
    evaluation,
  };
};

export const defenseTechniqueDataComponents = async (context: AuthContext, user: AuthUser, view: DefenseTechniqueView): Promise<DefenseDataComponentEvidenceView[]> => {
  const { evaluated, evaluation } = view;
  const inferredIds = evaluated.platforms.flatMap((p) => p.inferred_data_component_ids);
  const ids = uniq([...evaluated.data_component_ids, ...evaluated.platforms.flatMap((p) => p.data_component_ids), ...inferredIds]);
  const dataComponents = await findByIdsChunked<BasicStoreEntity>(context, user, ids, { type: ENTITY_TYPE_DATA_COMPONENT });
  return dataComponents
    .map((dataComponent) => ({
      dataComponent,
      providedBy: evaluated.platforms.filter((p) => p.data_component_ids.includes(dataComponent.internal_id))
        .map((p) => evaluation.platformById.get(p.platform_id)).filter((p): p is DefensePlatformView => !!p),
      inferredBy: evaluated.platforms.filter((p) => p.inferred_data_component_ids.includes(dataComponent.internal_id))
        .map((p) => evaluation.platformById.get(p.platform_id)).filter((p): p is DefensePlatformView => !!p),
    }))
    .sort((a, b) => (b.providedBy.length + b.inferredBy.length) - (a.providedBy.length + a.inferredBy.length) || a.dataComponent.name.localeCompare(b.dataComponent.name));
};

const deploymentsByRule = (view: DefenseTechniqueView) => {
  const { coverage, evaluation } = view;
  const result = new Map<string, Array<{ platform: DefensePlatformView; status: string }>>();
  (coverage?.platforms ?? []).forEach((vector) => {
    const platform = evaluation.platformById.get(vector.platform_id);
    if (!platform || !evaluation.can(vector.platform_id)) return;
    if (evaluation.selected && !evaluation.selected.includes(vector.platform_id)) return;
    vector.deployments
      .filter((d) => evaluation.can(d.id) && evaluation.can(d.rel) && evaluation.can(d.indicates))
      .forEach((d) => {
        result.set(d.id, [...(result.get(d.id) ?? []), { platform, status: d.status }]);
      });
  });
  return result;
};

export const defenseTechniqueRules = async (context: AuthContext, user: AuthUser, view: DefenseTechniqueView): Promise<DefenseRuleEvidenceView[]> => {
  const deployments = deploymentsByRule(view);
  const ids = uniq([...view.evaluated.rule_ids, ...deployments.keys()]);
  const [indicators, mappings] = await Promise.all([
    findByIdsChunked<BasicStoreEntityIndicator>(context, user, ids, { type: ENTITY_TYPE_INDICATOR }),
    listAllDefenseLogsourceMappings(context, SYSTEM_USER),
  ]);
  const activeMappings = mappings.filter((m) => m.active);
  const ranked = rankRuleCandidates(indicators.map((indicator) => ({
    id: indicator.internal_id,
    x_opencti_rule_status: indicator.x_opencti_rule_status,
    x_opencti_rule_level: indicator.x_opencti_rule_level,
    compatible: (deployments.get(indicator.internal_id) ?? []).length > 0,
    indicator,
  })));
  return ranked.map(({ indicator }) => ({
    indicator,
    deployments: deployments.get(indicator.internal_id) ?? [],
    required_data_components: mapLogsourceToDataComponents(indicator.x_opencti_rule_logsource, activeMappings),
  }));
};

export const defenseTechniqueValidations = async (context: AuthContext, user: AuthUser, view: DefenseTechniqueView): Promise<DefenseValidationEvidenceView[]> => {
  const { coverage, evaluation } = view;
  const accessible = (coverage?.validations ?? []).filter((v) => evaluation.can(v.id) && evaluation.can(v.rel));
  if (accessible.length === 0) return [];
  const results = await findByIdsChunked<BasicStoreEntity>(context, user, accessible.map((v) => v.id), { type: ENTITY_TYPE_SECURITY_COVERAGE_RESULT });
  const resultsById = new Map(results.map((r) => [r.internal_id, r]));
  const coverageIds = uniq(accessible.map((v) => v.coverage_id).filter((c): c is string => !!c));
  const coverages = await findByIdsChunked<BasicStoreEntity>(context, user, coverageIds, { type: ENTITY_TYPE_SECURITY_COVERAGE });
  const coveragesById = new Map(coverages.map((c) => [c.internal_id, c]));
  const toScores = (scores: DefenseScore[]) => scores.map((s) => ({ coverage_name: s.name, coverage_score: Math.round(s.score) }));
  return accessible
    .filter((v) => resultsById.has(v.id))
    .map((validation) => {
      const platforms = (coverage?.platforms ?? [])
        .filter((p) => evaluation.can(p.platform_id) && evaluation.platformById.has(p.platform_id))
        .flatMap((p) => p.validations.filter((pv) => pv.rel === validation.rel).map((pv) => ({
          platform: evaluation.platformById.get(p.platform_id) as DefensePlatformView,
          status: pv.status,
          scores: toScores(pv.scores),
        })));
      return {
        result: resultsById.get(validation.id) as BasicStoreEntity,
        securityCoverage: validation.coverage_id ? coveragesById.get(validation.coverage_id) ?? null : null,
        status: validation.status,
        last_result_at: validation.last_result_at,
        scores: toScores(validation.scores),
        platforms,
      };
    })
    .sort((a, b) => new Date(b.last_result_at ?? 0).getTime() - new Date(a.last_result_at ?? 0).getTime());
};

export const defenseTechniqueMitigations = async (context: AuthContext, user: AuthUser, view: DefenseTechniqueView) => {
  return findByIdsChunked<any>(context, user, view.evaluated.mitigation_ids, { type: ENTITY_TYPE_COURSE_OF_ACTION });
};

export const defenseTechniqueThreats = async (context: AuthContext, user: AuthUser, view: DefenseTechniqueView): Promise<DefenseThreatEvidenceView[]> => {
  const usages = view.evaluation.overlay.usages.get(view.technique.id) ?? [];
  const best = new Map<string, { relationship_id: string; confidence: number }>();
  usages.forEach((u) => {
    const current = best.get(u.threat_id);
    if (!current || u.confidence > current.confidence) best.set(u.threat_id, { relationship_id: u.relationship_id, confidence: u.confidence });
  });
  const threats = await findByIdsChunked<BasicStoreEntity>(context, user, Array.from(best.keys()), { type: DEFENSE_THREAT_TYPES });
  return threats
    .map((threat) => ({ threat, ...(best.get(threat.internal_id) as { relationship_id: string; confidence: number }) }))
    .sort((a, b) => b.confidence - a.confidence || a.threat.name.localeCompare(b.threat.name));
};
// endregion

// region gaps
const buildGapView = (
  technique: DefenseTechniqueEntry,
  cell: DefenseCell,
  platformId: string,
  evaluation: Evaluation,
): DefenseGapView => {
  const platformCell = cellForPlatform(cell, platformId);
  const { threat_weight, threats_count } = threatFigures(evaluation.overlay, technique.id);
  const { standardId, internalId } = defenseGapId(technique.id, platformId);
  const platform = platformId === DEFENSE_AGGREGATE_PLATFORM ? null : evaluation.platformById.get(platformId) ?? null;
  const platformDataComponents = uniq([...platformCell.data_component_ids, ...platformCell.inferred_data_component_ids]);
  return {
    id: internalId,
    internal_id: internalId,
    standard_id: standardId,
    entity_type: ENTITY_TYPE_DEFENSE_GAP,
    parent_types: getParentTypes(ENTITY_TYPE_DEFENSE_GAP),
    name: `${technique.x_mitre_id ? `[${technique.x_mitre_id}] ` : ''}${technique.name} - ${platform?.name ?? 'All platforms'}`,
    attack_pattern_id: technique.id,
    x_mitre_id: technique.x_mitre_id,
    attack_pattern_name: technique.name,
    platform_id: platformId,
    platform,
    kill_chain_phase_ids: technique.kill_chain_phase_ids,
    level: platformCell.level,
    telemetry: platformCell.telemetry,
    detection: platformCell.detection,
    validated: platformCell.validated,
    last_result_at: platformCell.last_result_at,
    recommended_action: platformCell.recommended_action,
    threat_weight,
    threats_count,
    priority: computeGapPriority(platformCell.level, threat_weight),
    status: platformCell.level >= DEFENSE_LEVEL_VALIDATED ? DEFENSE_GAP_STATUS_CLOSED : DEFENSE_GAP_STATUS_OPEN,
    validation_requests: [],
    required_data_component_ids: cell.data_component_ids.filter((id) => !platformDataComponents.includes(id)),
    available_rule_ids: cell.rule_ids,
    deployed_rule_ids: platformCell.rule_ids,
    platform_data_component_ids: platformDataComponents,
  };
};

const OPEN_LEVELS = [0, 1, 2, 3];

const matchGapFilter = (gap: DefenseGapView, filter: DefenseGapsFilter | null | undefined) => {
  const levels = filter?.levels && filter.levels.length > 0 ? filter.levels : OPEN_LEVELS;
  if (!levels.includes(gap.level)) return false;
  if (filter?.recommended_actions && filter.recommended_actions.length > 0 && !filter.recommended_actions.includes(gap.recommended_action as never)) return false;
  if (filter?.killChainPhaseIds && filter.killChainPhaseIds.length > 0 && !gap.kill_chain_phase_ids.some((k) => filter.killChainPhaseIds?.includes(k))) return false;
  if (filter?.onlyUsedByThreats && gap.threats_count === 0) return false;
  if (filter?.search) {
    const search = filter.search.trim().toLowerCase();
    if (search.length > 0 && !`${gap.x_mitre_id ?? ''} ${gap.attack_pattern_name} ${gap.platform?.name ?? ''}`.toLowerCase().includes(search)) return false;
  }
  return true;
};

const GAP_SORTERS: Record<string, (a: DefenseGapView, b: DefenseGapView) => number> = {
  priority: (a, b) => a.priority - b.priority,
  level: (a, b) => a.level - b.level,
  threat_weight: (a, b) => a.threat_weight - b.threat_weight,
  x_mitre_id: (a, b) => (a.x_mitre_id ?? '').localeCompare(b.x_mitre_id ?? '', undefined, { numeric: true }),
  name: (a, b) => a.attack_pattern_name.localeCompare(b.attack_pattern_name),
  platform: (a, b) => (a.platform?.name ?? '').localeCompare(b.platform?.name ?? ''),
};

const sortGaps = (gaps: DefenseGapView[], orderBy?: DefenseGapsOrdering | null, orderMode?: OrderingMode | null) => {
  const key = orderBy ?? 'priority';
  const mode = orderMode ?? (key === 'priority' || key === 'threat_weight' ? 'desc' : 'asc');
  const sorter = GAP_SORTERS[key] ?? GAP_SORTERS.priority;
  const direction = mode === 'desc' ? -1 : 1;
  return [...gaps].sort((a, b) => {
    const primary = sorter(a, b) * direction;
    if (primary !== 0) return primary;
    return a.level - b.level || GAP_SORTERS.x_mitre_id(a, b) || GAP_SORTERS.platform(a, b);
  });
};

interface GapsArgs {
  platformIds?: ReadonlyArray<string> | null;
  threatScope?: DefenseThreatScope | null;
  filter?: DefenseGapsFilter | null;
  orderBy?: DefenseGapsOrdering | null;
  orderMode?: OrderingMode | null;
}

const computeGapViews = async (context: AuthContext, user: AuthUser, args: GapsArgs) => {
  const evaluation = await prepareEvaluation(context, user, args.platformIds, args.threatScope);
  const platformKeys = evaluation.selected ?? [DEFENSE_AGGREGATE_PLATFORM];
  const gaps: DefenseGapView[] = [];
  evaluation.snapshot.techniques.filter((t) => evaluation.can(t.id)).forEach((technique) => {
    const cell = evaluateCoverage(technique.id, technique.coverage, evaluation.can, evaluation.selected);
    platformKeys.forEach((platformId) => {
      const gap = buildGapView(technique, cell, platformId, evaluation);
      if (matchGapFilter(gap, args.filter)) gaps.push(gap);
    });
  });
  return { gaps: sortGaps(gaps, args.orderBy, args.orderMode), evaluation };
};

const attachGapRecords = async (context: AuthContext, user: AuthUser, gaps: DefenseGapView[]) => {
  if (gaps.length === 0) return gaps;
  const records = await findByIdsChunked<BasicStoreEntityDefenseGap>(context, SYSTEM_USER, gaps.map((g) => g.internal_id), { type: ENTITY_TYPE_DEFENSE_GAP });
  const recordsById = new Map(records.map((r) => [r.internal_id, r]));
  // Gap records are shared: a request is only shown when the reader can access what it references
  const referencedIds = records.flatMap((r) => (r.validation_requests ?? []).flatMap((request) => [
    request.security_coverage_id,
    request.grouping_id,
    ...(request.threat_id ? [request.threat_id] : []),
  ]));
  const accessible = await findByIdsChunked<BasicStoreEntity>(context, user, referencedIds, { baseData: true });
  const accessibleIds = new Set(accessible.map((element) => element.internal_id));
  return gaps.map((gap) => {
    const record = recordsById.get(gap.internal_id);
    if (!record) return gap;
    const requests = (record.validation_requests ?? [])
      .filter((request) => accessibleIds.has(request.security_coverage_id) && accessibleIds.has(request.grouping_id))
      .map((request) => ({ ...request, threat_id: request.threat_id && accessibleIds.has(request.threat_id) ? request.threat_id : undefined }));
    return {
      ...gap,
      opened_at: record.opened_at,
      validation_requests: requests,
      last_validation_requested_at: requests.length > 0 ? record.last_validation_requested_at : undefined,
    };
  });
};

const encodeOffset = (offset: number) => Buffer.from(`defense-gap:${offset}`, 'utf-8').toString('base64');
const decodeOffset = (cursor: string | null | undefined) => {
  if (!cursor) return 0;
  const decoded = Buffer.from(cursor, 'base64').toString('utf-8');
  const offset = Number(decoded.replace('defense-gap:', ''));
  if (!decoded.startsWith('defense-gap:') || !Number.isInteger(offset) || offset < 0) {
    throw FunctionalError('Invalid defense gaps cursor');
  }
  return offset + 1;
};

export const findDefenseGaps = async (context: AuthContext, user: AuthUser, args: GapsArgs & { first?: number | null; after?: string | null }) => {
  const first = Math.min(Math.max(args.first ?? DEFAULT_GAPS_PAGE_SIZE, 1), MAX_GAPS_PAGE_SIZE);
  const start = decodeOffset(args.after);
  const { gaps } = await computeGapViews(context, user, args);
  const page = await attachGapRecords(context, user, gaps.slice(start, start + first));
  const edges = page.map((node, index) => ({ cursor: encodeOffset(start + index), node }));
  return {
    edges,
    pageInfo: {
      startCursor: edges.length > 0 ? edges[0].cursor : '',
      endCursor: edges.length > 0 ? edges[edges.length - 1].cursor : '',
      hasNextPage: start + first < gaps.length,
      hasPreviousPage: start > 0,
      globalCount: gaps.length,
    },
  };
};

export const defenseTechniqueGaps = async (context: AuthContext, view: DefenseTechniqueView) => {
  const { evaluation, technique, evaluated } = view;
  const platformKeys = [DEFENSE_AGGREGATE_PLATFORM, ...(evaluation.selected ?? evaluation.platforms.map((p) => p.id))];
  const gaps = platformKeys.map((platformId) => buildGapView(technique, evaluated, platformId, evaluation));
  return attachGapRecords(context, user, gaps);
};

export const defenseGapRequiredDataComponents = async (context: AuthContext, user: AuthUser, gap: DefenseGapView) => {
  return findByIdsChunked<BasicStoreEntityDataComponent>(context, user, gap.required_data_component_ids, { type: ENTITY_TYPE_DATA_COMPONENT });
};

// Field resolvers run once per node: share the full lists they need for the duration of one request
const requestCaches = new WeakMap<AuthContext, Map<string, Promise<unknown>>>();
const cachedForRequest = <T>(context: AuthContext, key: string, loader: () => Promise<T>): Promise<T> => {
  let cache = requestCaches.get(context);
  if (!cache) {
    cache = new Map();
    requestCaches.set(context, cache);
  }
  if (!cache.has(key)) {
    const promise = loader();
    promise.catch(() => cache?.delete(key));
    cache.set(key, promise);
  }
  return cache.get(key) as Promise<T>;
};

export const listDataComponentNames = (context: AuthContext, user: AuthUser) => {
  return cachedForRequest(context, `data-components:${user.id}`, () => fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_DATA_COMPONENT], {
    baseData: true,
    baseFields: ['name'],
  }));
};

export const resolveMappingDataComponents = async (context: AuthContext, user: AuthUser, dataComponentNames: ReadonlyArray<string>) => {
  const names = new Set(dataComponentNames.map((n) => n.toLowerCase()));
  const dataComponents = await listDataComponentNames(context, user);
  return dataComponents.filter((dc) => names.has((dc.name ?? '').toLowerCase()));
};

const loadRuleCandidates = async (
  context: AuthContext,
  user: AuthUser,
  gaps: DefenseGapView[],
): Promise<Map<string, BasicStoreEntityIndicator[]>> => {
  const candidateIds = uniq(gaps.flatMap((g) => g.available_rule_ids.filter((id) => !g.deployed_rule_ids.includes(id))));
  const [indicators, mappings, dataComponents] = await Promise.all([
    findByIdsChunked<BasicStoreEntityIndicator>(context, user, candidateIds, { type: ENTITY_TYPE_INDICATOR }),
    cachedForRequest(context, 'mappings', () => listAllDefenseLogsourceMappings(context, SYSTEM_USER)),
    listDataComponentNames(context, SYSTEM_USER),
  ]);
  const activeMappings = mappings.filter((m) => m.active);
  const dataComponentIdsByName = new Map<string, string[]>();
  dataComponents.forEach((dc) => {
    const key = (dc.name ?? '').toLowerCase();
    dataComponentIdsByName.set(key, [...(dataComponentIdsByName.get(key) ?? []), dc.internal_id]);
  });
  const indicatorsById = new Map(indicators.map((i) => [i.internal_id, i]));
  const result = new Map<string, BasicStoreEntityIndicator[]>();
  gaps.forEach((gap) => {
    const candidates = gap.available_rule_ids
      .filter((id) => !gap.deployed_rule_ids.includes(id))
      .map((id) => indicatorsById.get(id))
      .filter((i): i is BasicStoreEntityIndicator => !!i)
      .map((indicator) => {
        const required = mapLogsourceToDataComponents(indicator.x_opencti_rule_logsource, activeMappings)
          .flatMap((name) => dataComponentIdsByName.get(name.toLowerCase()) ?? []);
        const compatible = gap.platform_id === DEFENSE_AGGREGATE_PLATFORM
          || required.length === 0
          || required.some((id) => gap.platform_data_component_ids.includes(id));
        return { id: indicator.internal_id, x_opencti_rule_status: indicator.x_opencti_rule_status, x_opencti_rule_level: indicator.x_opencti_rule_level, compatible, indicator };
      });
    result.set(gap.id, rankRuleCandidates(candidates).map((c) => c.indicator));
  });
  return result;
};

export const defenseGapRuleCandidates = async (context: AuthContext, user: AuthUser, gap: DefenseGapView, first?: number | null) => {
  const candidates = await loadRuleCandidates(context, user, [gap]);
  return (candidates.get(gap.id) ?? []).slice(0, Math.min(Math.max(first ?? DEFAULT_RULE_CANDIDATES, 1), 50));
};

export const defenseGapValidationCoverage = async (context: AuthContext, user: AuthUser, request: DefenseGapValidationRequest) => {
  return storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, request.security_coverage_id, ENTITY_TYPE_SECURITY_COVERAGE);
};

const EXPORT_HEADERS = [
  'technique_id',
  'technique',
  'platform',
  'level',
  'telemetry',
  'detection',
  'validated',
  'last_validation',
  'threats',
  'threat_weight',
  'priority',
  'recommended_action',
  'rule_candidates',
  'validation_requested_at',
];

export const exportDefenseGaps = async (context: AuthContext, user: AuthUser, args: GapsArgs) => {
  const { gaps } = await computeGapViews(context, user, args);
  const rows = await attachGapRecords(context, user, gaps.slice(0, MAX_EXPORT_ROWS));
  const candidates = await loadRuleCandidates(context, user, rows);
  const csv = buildCsv(EXPORT_HEADERS, rows.map((gap) => [
    gap.x_mitre_id ?? '',
    gap.attack_pattern_name,
    gap.platform?.name ?? 'All platforms',
    gap.level,
    gap.telemetry ? 'yes' : 'no',
    gap.detection,
    gap.validated,
    gap.last_result_at ?? '',
    gap.threats_count,
    gap.threat_weight,
    gap.priority,
    gap.recommended_action,
    (candidates.get(gap.id) ?? []).slice(0, 3).map((i) => i.name),
    gap.last_validation_requested_at ?? '',
  ]));
  await addDefenseGapExportCount();
  if (gaps.length > MAX_EXPORT_ROWS) {
    logApp.warn('[DEFENSE-COVERAGE] Gap export truncated', { total: gaps.length, exported: MAX_EXPORT_ROWS });
  }
  return csv;
};
// endregion

// region validation
const GAP_TRACKING_SCRIPT = `
  if (ctx._source.validation_requests == null) { ctx._source.validation_requests = []; }
  ctx._source.validation_requests.add(params.request);
  ctx._source.last_validation_requested_at = params.request.requested_at;
`;

const trackValidationRequest = async (
  context: AuthContext,
  attackPatterns: BasicStoreEntity[],
  platformIds: string[],
  request: DefenseGapValidationRequest,
) => {
  const operations = [];
  for (let index = 0; index < attackPatterns.length; index += 1) {
    const attackPattern = attackPatterns[index];
    for (let platformIndex = 0; platformIndex < platformIds.length; platformIndex += 1) {
      const platformId = platformIds[platformIndex];
      const { standardId, internalId } = defenseGapId(attackPattern.internal_id, platformId);
      const { element } = await buildEntityData(context, SYSTEM_USER, {
        internal_id: internalId,
        standard_id: standardId,
        name: `${(attackPattern as unknown as { x_mitre_id?: string }).x_mitre_id ?? ''} ${attackPattern.name}`.trim(),
        attack_pattern_id: attackPattern.internal_id,
        platform_id: platformId,
        level: 0,
        status: DEFENSE_GAP_STATUS_OPEN,
        opened_at: request.requested_at,
        computed_at: request.requested_at,
        validation_requests: [request],
        last_validation_requested_at: request.requested_at,
        created_at: request.requested_at,
        updated_at: request.requested_at,
      }, ENTITY_TYPE_DEFENSE_GAP);
      const { _index: _ignored, ...upsertDoc } = element as Record<string, unknown>;
      operations.push(
        { update: { _index: INDEX_INTERNAL_OBJECTS, _id: internalId, retry_on_conflict: 5 } },
        { script: { source: GAP_TRACKING_SCRIPT, lang: 'painless', params: { request } }, upsert: upsertDoc },
      );
    }
  }
  if (operations.length > 0) {
    await elBulk(context, { refresh: true, body: operations });
  }
  return operations.length / 2;
};

/**
 * Validate a set of techniques through OpenAEV, with the existing Security Coverage flow:
 * a Grouping holds the chosen techniques (and the threat if any), a Security Coverage covers it, and the
 * OpenAEV enrichment generates a scenario restricted to these techniques. The request is tracked on the gaps.
 */
export const validateDefenseGaps = async (context: AuthContext, user: AuthUser, input: DefenseValidationInput): Promise<DefenseValidationResultView> => {
  const attackPatternIds = uniq(input.attackPatternIds ?? []);
  if (attackPatternIds.length === 0) {
    throw FunctionalError('Select at least one technique to validate');
  }
  if (attackPatternIds.length > MAX_VALIDATION_TECHNIQUES) {
    throw FunctionalError(`A validation request cannot contain more than ${MAX_VALIDATION_TECHNIQUES} techniques`, { count: attackPatternIds.length });
  }
  const attackPatterns = await findByIdsChunked<BasicStoreEntity>(context, user, attackPatternIds, { type: ENTITY_TYPE_ATTACK_PATTERN });
  if (attackPatterns.length !== attackPatternIds.length) {
    throw FunctionalError('Some techniques of the validation request cannot be found', { expected: attackPatternIds.length, found: attackPatterns.length });
  }
  let threat: BasicStoreEntity | undefined;
  if (input.threatId) {
    threat = await storeLoadById<BasicStoreEntity>(context, user, input.threatId, DEFENSE_THREAT_TYPES);
    if (!threat) {
      throw FunctionalError('The threat of the validation request cannot be found', { threatId: input.threatId });
    }
  }
  const platforms = await findDefensePlatforms(context, user);
  const requestedPlatforms = uniq(input.platformIds ?? []);
  const unknownPlatforms = requestedPlatforms.filter((id) => !platforms.some((p) => p.id === id));
  if (unknownPlatforms.length > 0) {
    throw FunctionalError('Some security platforms of the validation request cannot be found', { platformIds: unknownPlatforms });
  }
  const requestedAt = now();
  const name = input.name ?? `Defense validation - ${threat?.name ?? `${attackPatterns.length} techniques`} - ${requestedAt.substring(0, 10)}`;
  const grouping = await addGrouping(context, user, {
    name,
    description: input.description ?? 'Techniques selected from the defense gap backlog for validation with OpenAEV.',
    context: 'defense-validation',
    objects: [...attackPatterns.map((ap) => ap.internal_id), ...(threat ? [threat.internal_id] : [])],
  });
  const securityCoverage = await addSecurityCoverage(context, user, {
    name,
    description: input.description,
    objectCovered: grouping.id,
    auto_enrichment_disable: false,
    periodicity: input.periodicity,
    duration: input.duration,
    type_affinity: input.type_affinity,
    platforms_affinity: input.platforms_affinity,
  });
  const request: DefenseGapValidationRequest = {
    security_coverage_id: securityCoverage.id,
    grouping_id: grouping.id,
    ...(threat ? { threat_id: threat.internal_id } : {}),
    requested_at: requestedAt,
    requested_by: user.id,
  };
  const gapsCount = await trackValidationRequest(context, attackPatterns, [DEFENSE_AGGREGATE_PLATFORM, ...requestedPlatforms], request);
  await addDefenseValidationRequestCount();
  return { securityCoverage, grouping, gaps_count: gapsCount };
};
// endregion

// region telemetry from log sources
export const addPlatformProvidesFromLogsources = async (
  context: AuthContext,
  user: AuthUser,
  platformId: string,
  logsources: ReadonlyArray<DefenseLogsourceInput>,
): Promise<DefenseProvidesResultView> => {
  if (logsources.length === 0 || logsources.length > MAX_LOGSOURCES) {
    throw FunctionalError(`Provide between 1 and ${MAX_LOGSOURCES} log sources`, { count: logsources.length });
  }
  const platform = await storeLoadById<BasicStoreEntity>(context, user, platformId, [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, ENTITY_TYPE_IDENTITY_SYSTEM]);
  if (!platform) {
    throw FunctionalError('Security platform or system not found', { platformId });
  }
  const mappings = (await listAllDefenseLogsourceMappings(context, SYSTEM_USER)).filter((m) => m.active);
  const names = uniq(logsources.flatMap((logsource) => mapLogsourceToDataComponents(logsource, mappings)));
  const dataComponents = await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_DATA_COMPONENT], { baseData: true, baseFields: ['name'] });
  const byName = new Map<string, BasicStoreEntity[]>();
  dataComponents.forEach((dc) => {
    const key = (dc.name ?? '').toLowerCase();
    byName.set(key, [...(byName.get(key) ?? []), dc]);
  });
  const matched = names.flatMap((name) => byName.get(name.toLowerCase()) ?? []);
  const unmatched = names.filter((name) => !byName.has(name.toLowerCase()));
  for (let index = 0; index < matched.length; index += 1) {
    await addStixCoreRelationship(context, user, {
      fromId: platform.internal_id,
      toId: matched[index].internal_id,
      relationship_type: RELATION_PROVIDES,
      description: 'Declared from log sources through the defense matrix log source mapping',
    });
  }
  const created = await findByIdsChunked<BasicStoreEntity>(context, user, matched.map((m) => m.internal_id), { type: ENTITY_TYPE_DATA_COMPONENT });
  return { created_count: matched.length, dataComponents: created, unmatched_data_components: unmatched };
};
// endregion

// region status
export const requestDefenseCoverageRecompute = async () => {
  await requestFullDefenseCoverageComputation();
  return true;
};

export const getDefenseCoverageStatus = async (context: AuthContext) => {
  const snapshot = await getDefenseSnapshot(context);
  return {
    computed_at: computedAtOf(snapshot),
    last_full_computation: await getLastFullComputation(),
    full_computation_requested: await isFullComputationRequested(),
  };
};
// endregion

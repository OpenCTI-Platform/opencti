import * as R from 'ramda';
import DataLoader from 'dataloader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { fullEntitiesList, fullRelationsList, internalFindByIds, storeLoadById } from '../../database/middleware-loader';
import { elBulk } from '../../database/engine';
import { buildEntityData } from '../../database/data-builder';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { isUserHasCapability, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { KNOWLEDGE_FRONTEND_EXPORT } from '../../schema/general';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../schema/stixDomainObject';
import { RELATION_PROVIDES } from '../../schema/stixCoreRelationship';
import { addStixCoreRelationship } from '../../domain/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR, type BasicStoreEntityIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { type BasicStoreEntitySecurityCoverage, ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { connectorsForEnrichment } from '../../database/repository';
import type { BasicStoreEntityDataComponent } from '../dataComponent/dataComponent-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { addSecurityCoverage } from '../securityCoverage/securityCoverage-domain';
import { addGrouping } from '../grouping/grouping-domain';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { deleteElementById } from '../../database/middleware';
import { addExternalReference } from '../../domain/externalReference';
import { addDefenseGapExportCount, addDefenseValidationRequestCount } from '../../manager/telemetryManager';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS, wait } from '../../database/utils';
import { logApp } from '../../config/conf';
import type { DefenseGapsFilter, DefenseGapsOrdering, DefenseLogsourceInput, DefenseValidationInput, OrderingMode } from '../../generated/graphql';
import { DefenseValidationRequestStatus, FilterMode } from '../../generated/graphql';
import { ENTITY_TYPE_WORK } from '../../schema/internalObject';
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
  buildValidationTargets,
  type DefenseValidationTarget,
  cellForPlatform,
  computeGapPriority,
  computeThreatWeight,
  countEffectiveTechniques,
  defaultValidationName,
  evaluateCoverage,
  gapPlatformEvidence,
  mapLogsourceToDataComponents,
  rankRuleCandidates,
  validationEvidencePool,
  visibleParentId,
} from './defenseCoverage-utils';
import { type DefensePlatform, defenseGapId, loadDefensePlatforms } from './defenseCoverage-compute';
import { type DefenseSnapshot, type DefenseTechniqueEntry, type DefenseThreatScope, getAccessPredicate, getDefenseSnapshot, getThreatOverlay } from './defenseCoverage-reader';
import {
  clearPendingValidationTracking,
  getLastFullComputation,
  isFullComputationRequested,
  isFullComputationRunning,
  listPendingValidationTrackings,
  queuePendingValidationTracking,
  requestFullDefenseCoverageComputation,
} from './defenseCoverage-state';
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
const EXPORT_BATCH_SIZE = 2000;
export const DEFENSE_GAPS_EXPORT_MAX = 10000;
const MAX_VALIDATION_TECHNIQUES = 200;
// Gaps a validation request is tracked on (its techniques on every platform of the request): the techniques limit
// alone does not bound them, every requested platform multiplies them
const MAX_VALIDATION_GAPS = 2000;
const TRACKING_BULK_SIZE = 500;
// Attempts to track a created validation request on its gaps, and the delay between them (grows with the attempt)
const TRACKING_ATTEMPTS = 3;
const TRACKING_RETRY_DELAY = 500;
const MAX_PENDING_TRACKINGS_PER_RUN = 100;
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
  existing_count: number;
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
  // A selection left empty by deleted or inaccessible platforms falls back to every platform, as the UI shows it
  const validIds = uniq((platformIds ?? []).filter((id) => platformById.has(id)));
  const selected = validIds.length > 0 ? validIds : undefined;
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

const toCellView = (technique: DefenseTechniqueEntry, cell: DefenseCell, overlay: DefenseThreatOverlay, can: AccessPredicate): DefenseMatrixCellView => ({
  attack_pattern_id: technique.id,
  x_mitre_id: technique.x_mitre_id,
  name: technique.name,
  parent_attack_pattern_id: visibleParentId(technique, can),
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
  const cells = techniques.map((technique) => toCellView(technique, evaluateCoverage(technique.id, technique.coverage, can, selected), overlay, can));
  const cellsById = new Map(cells.map((c) => [c.attack_pattern_id, c]));
  const effective = countEffectiveTechniques(cells);
  const levels = emptyLevels();
  const threatLevels = emptyLevels();
  effective.forEach((value) => {
    levels[value.level] += 1;
    if (value.used) threatLevels[value.threat_level] += 1;
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
        phaseThreatLevels[value.threat_level] += 1;
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
    cell: toCellView(technique, evaluated, evaluation.overlay, evaluation.can),
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
  const { coverage, evaluation, evaluated } = view;
  // Only the results behind the displayed cell: the ones of the selected platforms (and the unattributed ones without selection)
  const contributing = new Set(evaluated.coverage_result_ids);
  const accessible = validationEvidencePool(coverage).filter((v) => contributing.has(v.id) && evaluation.can(v.id) && evaluation.can(v.rel));
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
        .filter((p) => !evaluation.selected || evaluation.selected.includes(p.platform_id))
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
  const provided = gapPlatformEvidence(cell, platformId);
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
    required_data_component_ids: cell.data_component_ids.filter((id) => !provided.data_component_ids.includes(id)),
    available_rule_ids: cell.rule_ids,
    deployed_rule_ids: provided.rule_ids,
    platform_data_component_ids: provided.data_component_ids,
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

/**
 * The first `limit` gaps of the backlog in the requested order, and the number of gaps matching the filter. At most
 * twice `limit` views are held at once: the list is sorted and cut back to `limit` whenever it reaches that size, which
 * keeps exactly the first gaps of a full (stable) sort.
 */
const computeGapViews = async (context: AuthContext, user: AuthUser, args: GapsArgs, limit: number) => {
  const evaluation = await prepareEvaluation(context, user, args.platformIds, args.threatScope);
  const platformKeys = evaluation.selected ?? [DEFENSE_AGGREGATE_PLATFORM];
  const keepFirst = (list: DefenseGapView[]) => sortGaps(list, args.orderBy, args.orderMode).slice(0, limit);
  let gaps: DefenseGapView[] = [];
  let total = 0;
  evaluation.snapshot.techniques.filter((t) => evaluation.can(t.id)).forEach((technique) => {
    const cell = evaluateCoverage(technique.id, technique.coverage, evaluation.can, evaluation.selected);
    platformKeys.forEach((platformId) => {
      const gap = buildGapView(technique, cell, platformId, evaluation);
      if (matchGapFilter(gap, args.filter)) {
        total += 1;
        gaps.push(gap);
        if (gaps.length >= limit * 2) gaps = keepFirst(gaps);
      }
    });
  });
  return { gaps: keepFirst(gaps), total, evaluation };
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
    // The record dates the latest request of any reader: a restricted one must not date the gap
    const lastRequestedAt = R.last(R.sortBy((request) => new Date(request.requested_at).getTime(), requests))?.requested_at;
    return {
      ...gap,
      opened_at: record.opened_at,
      validation_requests: requests,
      last_validation_requested_at: lastRequestedAt,
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
  const { gaps, total, evaluation } = await computeGapViews(context, user, args, start + first);
  const page = await attachGapRecords(context, user, gaps.slice(start, start + first));
  const edges = page.map((node, index) => ({ cursor: encodeOffset(start + index), node }));
  return {
    threats_count: evaluation.overlay.threats_count,
    edges,
    pageInfo: {
      startCursor: edges.length > 0 ? edges[0].cursor : '',
      endCursor: edges.length > 0 ? edges[edges.length - 1].cursor : '',
      hasNextPage: start + first < total,
      hasPreviousPage: start > 0,
      globalCount: total,
    },
  };
};

export const defenseTechniqueGaps = async (context: AuthContext, user: AuthUser, view: DefenseTechniqueView) => {
  const { evaluation, technique, evaluated } = view;
  const platformKeys = [DEFENSE_AGGREGATE_PLATFORM, ...(evaluation.selected ?? evaluation.platforms.map((p) => p.id))];
  const gaps = platformKeys.map((platformId) => buildGapView(technique, evaluated, platformId, evaluation));
  return attachGapRecords(context, user, gaps);
};

// Field resolvers run once per node: the nodes of one page are resolved together, one lookup per field
const requestLoaders = new WeakMap<AuthContext, Map<string, unknown>>();
const loaderForRequest = <V, K = DefenseGapView>(context: AuthContext, key: string, batch: (keys: readonly K[]) => Promise<V[]>) => {
  let loaders = requestLoaders.get(context);
  if (!loaders) {
    loaders = new Map();
    requestLoaders.set(context, loaders);
  }
  let loader = loaders.get(key) as DataLoader<K, V> | undefined;
  if (!loader) {
    loader = new DataLoader<K, V>(batch, { cache: false });
    loaders.set(key, loader);
  }
  return loader;
};

export const defenseGapRequiredDataComponents = async (context: AuthContext, user: AuthUser, gap: DefenseGapView) => {
  const loader = loaderForRequest<BasicStoreEntityDataComponent[]>(context, `required-data-components:${user.id}`, async (gaps) => {
    const ids = uniq(gaps.flatMap((g) => g.required_data_component_ids));
    const dataComponents = await findByIdsChunked<BasicStoreEntityDataComponent>(context, user, ids, { type: ENTITY_TYPE_DATA_COMPONENT });
    const byId = new Map<string, BasicStoreEntityDataComponent>();
    dataComponents.forEach((dc) => {
      const stixIds = (dc as unknown as { x_opencti_stix_ids?: string[] }).x_opencti_stix_ids ?? [];
      [dc.internal_id, dc.standard_id, ...stixIds].forEach((id) => byId.set(id, dc));
    });
    return gaps.map((g) => {
      const resolved = new Map<string, BasicStoreEntityDataComponent>();
      g.required_data_component_ids.forEach((id) => {
        const dc = byId.get(id);
        if (dc) resolved.set(dc.internal_id, dc);
      });
      return Array.from(resolved.values());
    });
  });
  return loader.load(gap);
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
  const loader = loaderForRequest<BasicStoreEntityIndicator[]>(context, `rule-candidates:${user.id}`, async (gaps) => {
    const candidatesByGap = await loadRuleCandidates(context, user, [...gaps]);
    return gaps.map((g) => candidatesByGap.get(g.id) ?? []);
  });
  const candidates = await loader.load(gap);
  return candidates.slice(0, Math.min(Math.max(first ?? DEFAULT_RULE_CANDIDATES, 1), 50));
};

const loadValidationCoverages = async (context: AuthContext, user: AuthUser, coverageIds: readonly string[]) => {
  const coverages = await findByIdsChunked<BasicStoreEntitySecurityCoverage>(context, user, [...coverageIds], { type: ENTITY_TYPE_SECURITY_COVERAGE });
  const coveragesById = new Map(coverages.map((coverage) => [coverage.internal_id, coverage]));
  return coverageIds.map((id) => coveragesById.get(id) ?? null);
};

export const defenseGapValidationCoverage = async (context: AuthContext, user: AuthUser, request: DefenseGapValidationRequest) => {
  const loader = loaderForRequest<BasicStoreEntitySecurityCoverage | null, string>(context, `validation-coverages:${user.id}`, (ids) => {
    return loadValidationCoverages(context, user, ids);
  });
  return loader.load(request.security_coverage_id);
};

// A work moves to progress when a connector receives it, then to complete
const RECEIVED_WORK_STATUSES = ['progress', 'complete'];

const loadValidationStatuses = async (context: AuthContext, user: AuthUser, coverageIds: readonly string[]) => {
  const coverages = await loadValidationCoverages(context, user, coverageIds);
  const withResults = new Set(coverages
    .filter((coverage) => !!(coverage as unknown as { coverage_last_result?: string } | null)?.coverage_last_result)
    .map((coverage) => coverage?.internal_id));
  const awaitingIds = uniq(coverageIds.filter((id) => !withResults.has(id)));
  // Works are platform records: only whether a connector received the enrichment of the security coverage is used
  const receivedWorks = awaitingIds.length === 0 ? [] : await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_WORK], {
    indices: [READ_INDEX_HISTORY],
    baseData: true,
    baseFields: ['event_source_id'],
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['event_source_id'], values: awaitingIds }, { key: ['status'], values: RECEIVED_WORK_STATUSES }],
      filterGroups: [],
    },
  });
  const receivedIds = new Set(receivedWorks.map((work) => (work as unknown as { event_source_id?: string }).event_source_id));
  return coverageIds.map((id) => {
    if (withResults.has(id)) return DefenseValidationRequestStatus.Results;
    return receivedIds.has(id) ? DefenseValidationRequestStatus.Running : DefenseValidationRequestStatus.Waiting;
  });
};

/**
 * Where OpenAEV stands on a validation request: results received on its security coverage, the security coverage read
 * by an OpenAEV platform (its enrichment work was received) with no result yet, or waiting for an OpenAEV platform to
 * read it.
 */
export const defenseGapValidationStatus = async (context: AuthContext, user: AuthUser, request: DefenseGapValidationRequest) => {
  const loader = loaderForRequest<DefenseValidationRequestStatus, string>(context, `validation-statuses:${user.id}`, (ids) => {
    return loadValidationStatuses(context, user, ids);
  });
  return loader.load(request.security_coverage_id);
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
  // An export of the web interface: the platform grants it with its own capability, on top of the knowledge access
  if (!isUserHasCapability(user, KNOWLEDGE_FRONTEND_EXPORT)) {
    throw ForbiddenAccess();
  }
  // The first DEFENSE_GAPS_EXPORT_MAX gaps in the requested order are exported, records and rule candidates loaded by
  // bounded batches; the interface tells when the backlog holds more
  const { gaps: exported } = await computeGapViews(context, user, args, DEFENSE_GAPS_EXPORT_MAX);
  const lines: unknown[][] = [];
  for (let start = 0; start < exported.length; start += EXPORT_BATCH_SIZE) {
    const rows = await attachGapRecords(context, user, exported.slice(start, start + EXPORT_BATCH_SIZE));
    const candidates = await loadRuleCandidates(context, user, rows);
    rows.forEach((gap) => lines.push([
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
  }
  // The export is built: a usage counter that cannot be written must not fail it
  try {
    await addDefenseGapExportCount();
  } catch (error) {
    logApp.warn('[DEFENSE-COVERAGE] Gaps export not counted in the usage telemetry', { cause: error });
  }
  return buildCsv(EXPORT_HEADERS, lines);
};
// endregion

// region validation
// Idempotent: a retried tracking never appends the same request twice to a gap
const GAP_TRACKING_SCRIPT = `
  if (ctx._source.validation_requests == null) { ctx._source.validation_requests = []; }
  boolean tracked = false;
  for (existing in ctx._source.validation_requests) {
    if (existing.security_coverage_id == params.request.security_coverage_id) { tracked = true; }
  }
  if (tracked) {
    ctx.op = 'noop';
  } else {
    ctx._source.validation_requests.add(params.request);
    ctx._source.last_validation_requested_at = params.request.requested_at;
  }
`;

const trackValidationRequest = async (
  context: AuthContext,
  attackPatterns: BasicStoreEntity[],
  targets: DefenseValidationTarget[],
  request: DefenseGapValidationRequest,
) => {
  const attackPatternById = new Map(attackPatterns.map((attackPattern) => [attackPattern.internal_id, attackPattern]));
  const trackedTargets = targets.filter((target) => attackPatternById.has(target.attackPatternId));
  const chunks = R.splitEvery(TRACKING_BULK_SIZE, trackedTargets);
  for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += 1) {
    const chunk = chunks[chunkIndex];
    // An existing gap is updated in its own index (the write alias may point to a newer one after a rollover)
    const gapIds = chunk.map((target) => defenseGapId(target.attackPatternId, target.platformId).internalId);
    const existingGaps = await findByIdsChunked<BasicStoreEntity>(context, SYSTEM_USER, gapIds, { type: ENTITY_TYPE_DEFENSE_GAP, indices: [READ_INDEX_INTERNAL_OBJECTS] });
    const gapIndexById = new Map(existingGaps.map((gap) => [gap.internal_id, gap._index]));
    const operations = [];
    for (let index = 0; index < chunk.length; index += 1) {
      const { attackPatternId, platformId } = chunk[index];
      const attackPattern = attackPatternById.get(attackPatternId) as BasicStoreEntity;
      const { standardId, internalId } = defenseGapId(attackPattern.internal_id, platformId);
      const { element } = await buildEntityData(context, SYSTEM_USER, {
        internal_id: internalId,
        standard_id: standardId,
        entity_type: ENTITY_TYPE_DEFENSE_GAP,
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
        { update: { _index: gapIndexById.get(internalId) ?? INDEX_INTERNAL_OBJECTS, _id: internalId, retry_on_conflict: 5 } },
        { script: { source: GAP_TRACKING_SCRIPT, lang: 'painless', params: { request } }, upsert: upsertDoc },
      );
    }
    await elBulk(context, { refresh: true, body: operations });
  }
  return trackedTargets.length;
};

/**
 * Keep a validation request that could not be tracked on its gaps for the defense coverage manager, which tracks it
 * at its next run. Returns the number of gaps it will be tracked on.
 */
const queueValidationTracking = async (
  attackPatterns: BasicStoreEntity[],
  targets: DefenseValidationTarget[],
  request: DefenseGapValidationRequest,
  cause: unknown,
) => {
  const attackPatternIds = new Set(attackPatterns.map((attackPattern) => attackPattern.internal_id));
  const trackedTargets = targets.filter((target) => attackPatternIds.has(target.attackPatternId));
  try {
    await queuePendingValidationTracking({ request, targets: trackedTargets });
    logApp.warn('[DEFENSE-COVERAGE] Validation request created, its tracking on the gaps is queued', { cause, security_coverage_id: request.security_coverage_id });
    return trackedTargets.length;
  } catch (queueError) {
    logApp.error('[DEFENSE-COVERAGE] Validation request created but neither tracked on its gaps nor queued', {
      cause,
      queue_cause: queueError,
      request,
      targets: trackedTargets,
    });
    return 0;
  }
};

/**
 * Track the validation requests queued when their tracking failed at creation. Run by the defense coverage manager;
 * an entry stays queued until its tracking succeeds, and tracking it twice never appends the request twice.
 */
export const trackPendingValidationRequests = async (context: AuthContext) => {
  const queued = (await listPendingValidationTrackings()).slice(0, MAX_PENDING_TRACKINGS_PER_RUN);
  let tracked = 0;
  for (let index = 0; index < queued.length; index += 1) {
    const { id, pending } = queued[index];
    if (!pending) {
      logApp.error('[DEFENSE-COVERAGE] Unreadable queued validation tracking dropped', { security_coverage_id: id });
      await clearPendingValidationTracking(id);
    } else {
      try {
        const attackPatternIds = uniq(pending.targets.map((target) => target.attackPatternId));
        const attackPatterns = await findByIdsChunked<BasicStoreEntity>(context, SYSTEM_USER, attackPatternIds, { type: ENTITY_TYPE_ATTACK_PATTERN });
        await trackValidationRequest(context, attackPatterns, pending.targets, pending.request);
        await clearPendingValidationTracking(id);
        tracked += 1;
      } catch (error) {
        logApp.warn('[DEFENSE-COVERAGE] Queued validation request still not tracked on its gaps', { cause: error, security_coverage_id: id });
      }
    }
  }
  return tracked;
};

const parseValidationReferenceUrl = (value: string | null | undefined): URL | undefined => {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  let url: URL | undefined;
  try {
    url = new URL(trimmed);
  } catch {
    url = undefined;
  }
  if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:')) {
    throw FunctionalError('The external reference of a validation request must be an http or https URL');
  }
  return url;
};

/**
 * Validate a set of techniques through OpenAEV, with the existing Security Coverage flow:
 * a Grouping holds the chosen techniques (and the threat if any), a Security Coverage covers it, and the
 * OpenAEV enrichment generates a scenario restricted to these techniques. The request is tracked on the gaps.
 * An optional external reference URL links the Security Coverage back to what asked for the validation.
 */
export const validateDefenseGaps = async (context: AuthContext, user: AuthUser, input: DefenseValidationInput): Promise<DefenseValidationResultView> => {
  const gapRefs = input.gaps ?? [];
  const attackPatternIds = uniq([...(input.attackPatternIds ?? []), ...gapRefs.map((gap) => gap.attackPatternId)]);
  if (attackPatternIds.length === 0) {
    throw FunctionalError('Select at least one technique to validate');
  }
  const requestedName = input.name?.trim();
  if (typeof input.name === 'string' && (requestedName ?? '').length < 2) {
    throw FunctionalError('The name of a validation request must contain at least 2 characters other than spaces');
  }
  const referenceUrl = parseValidationReferenceUrl(input.external_reference_url);
  // Several ids may designate one technique: the ids only bound the loading, the techniques are counted once resolved
  if (attackPatternIds.length > MAX_VALIDATION_GAPS) {
    throw FunctionalError(`A validation request cannot designate its techniques with more than ${MAX_VALIDATION_GAPS} ids`, { count: attackPatternIds.length });
  }
  const found = await findByIdsChunked<BasicStoreEntity>(context, user, attackPatternIds, { type: ENTITY_TYPE_ATTACK_PATTERN });
  const attackPatterns = R.uniqBy((attackPattern) => attackPattern.internal_id, found);
  // The techniques and the gaps of the backlog may designate a technique by any of its ids
  const internalIdOf = new Map<string, string>();
  attackPatterns.forEach((attackPattern) => {
    const stixIds = (attackPattern as unknown as { x_opencti_stix_ids?: string[] }).x_opencti_stix_ids ?? [];
    [attackPattern.internal_id, attackPattern.standard_id, ...stixIds].forEach((id) => internalIdOf.set(id, attackPattern.internal_id));
  });
  const unresolvedIds = attackPatternIds.filter((id) => !internalIdOf.has(id));
  if (unresolvedIds.length > 0) {
    throw FunctionalError('Some techniques of the validation request cannot be found', { ids: unresolvedIds });
  }
  if (attackPatterns.length > MAX_VALIDATION_TECHNIQUES) {
    throw FunctionalError(`A validation request cannot contain more than ${MAX_VALIDATION_TECHNIQUES} techniques`, { count: attackPatterns.length });
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
  const gapPlatforms = gapRefs.map((gap) => gap.platformId).filter((id) => id !== DEFENSE_AGGREGATE_PLATFORM);
  const unknownPlatforms = uniq([...requestedPlatforms, ...gapPlatforms]).filter((id) => !platforms.some((p) => p.id === id));
  if (unknownPlatforms.length > 0) {
    throw FunctionalError('Some security platforms of the validation request cannot be found', { platformIds: unknownPlatforms });
  }
  const targets = buildValidationTargets(
    attackPatterns.map((attackPattern) => attackPattern.internal_id),
    requestedPlatforms,
    gapRefs.map((gap) => ({ attackPatternId: internalIdOf.get(gap.attackPatternId) ?? gap.attackPatternId, platformId: gap.platformId })),
  );
  if (targets.length > MAX_VALIDATION_GAPS) {
    throw FunctionalError(`A validation request cannot be tracked on more than ${MAX_VALIDATION_GAPS} gaps: validate fewer techniques or security platforms`, { count: targets.length });
  }
  // A Security Coverage is only enriched by the OpenAEV connectors active when it is created: without one, the request
  // would wait forever
  const validationConnectors = await connectorsForEnrichment(context, user, ENTITY_TYPE_SECURITY_COVERAGE, true);
  if (validationConnectors.length === 0) {
    throw FunctionalError('No active OpenAEV connector can validate techniques: connect OpenAEV to this platform first');
  }
  const requestedAt = now();
  const name = requestedName || defaultValidationName(attackPatterns.length, threat?.name, requestedAt);
  // An external reference is shared by every element with the same URL: it is resolved first and never removed
  const externalReference = referenceUrl
    ? await addExternalReference(context, user, { source_name: referenceUrl.hostname, url: referenceUrl.toString() })
    : undefined;
  // OpenAEV generates the scenario from the techniques; the threat, when given, names the request and stays in the Grouping
  // for the analysts; the security platforms record the gaps the request is tracked on. OpenAEV runs the scenario on
  // endpoints and attributes each result to the platform that produced it.
  const trackedPlatformIds = uniq([...requestedPlatforms, ...gapPlatforms]);
  const grouping = await addGrouping(context, user, {
    name,
    description: input.description ?? 'Techniques selected from the defense gap backlog for validation with OpenAEV, with the security platforms whose gaps track the request.',
    context: 'defense-validation',
    objects: [...attackPatterns.map((ap) => ap.internal_id), ...(threat ? [threat.internal_id] : []), ...trackedPlatformIds],
  });
  let securityCoverage: BasicStoreEntitySecurityCoverage;
  try {
    securityCoverage = await addSecurityCoverage(context, user, {
      name,
      description: input.description,
      objectCovered: grouping.id,
      auto_enrichment_disable: false,
      periodicity: input.periodicity,
      duration: input.duration,
      type_affinity: input.type_affinity,
      platforms_affinity: input.platforms_affinity,
      ...(externalReference ? { externalReferences: [externalReference.id] } : {}),
    });
  } catch (error) {
    // A failed request leaves no Grouping behind, so retrying it never duplicates one
    try {
      await deleteElementById(context, user, grouping.id, ENTITY_TYPE_CONTAINER_GROUPING);
    } catch (cleanupError) {
      logApp.error('[DEFENSE-COVERAGE] Grouping of a failed validation request not removed', { cause: cleanupError, grouping_id: grouping.id });
    }
    throw error;
  }
  const request: DefenseGapValidationRequest = {
    security_coverage_id: securityCoverage.id,
    grouping_id: grouping.id,
    ...(threat ? { threat_id: threat.internal_id } : {}),
    requested_at: requestedAt,
    requested_by: user.id,
  };
  // The validation exists from here: a tracking failure must not report a failed request that a retry would duplicate
  let gapsCount = 0;
  for (let attempt = 1; attempt <= TRACKING_ATTEMPTS; attempt += 1) {
    try {
      gapsCount = await trackValidationRequest(context, attackPatterns, targets, request);
      break;
    } catch (error) {
      if (attempt === TRACKING_ATTEMPTS) {
        gapsCount = await queueValidationTracking(attackPatterns, targets, request, error);
      } else {
        await wait(TRACKING_RETRY_DELAY * attempt);
      }
    }
  }
  // The request exists: a usage counter that cannot be written must not report it as failed, a retry would duplicate it
  try {
    await addDefenseValidationRequestCount();
  } catch (error) {
    logApp.warn('[DEFENSE-COVERAGE] Validation request not counted in the usage telemetry', { cause: error, security_coverage_id: securityCoverage.id });
  }
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
  // A revoked data component is withdrawn knowledge: no new telemetry is declared on it
  const dataComponents = (await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_DATA_COMPONENT], { baseData: true, baseFields: ['name', 'revoked'] }))
    .filter((dc) => !dc.revoked);
  const byName = new Map<string, BasicStoreEntity[]>();
  dataComponents.forEach((dc) => {
    const key = (dc.name ?? '').toLowerCase();
    byName.set(key, [...(byName.get(key) ?? []), dc]);
  });
  const matchedIds = uniq(names.flatMap((name) => byName.get(name.toLowerCase()) ?? []).map((dc) => dc.internal_id));
  const unmatched = names.filter((name) => !byName.has(name.toLowerCase()));
  const existing = matchedIds.length === 0 ? [] : await fullRelationsList<BasicStoreRelation>(context, user, RELATION_PROVIDES, {
    fromId: platform.internal_id,
    toId: matchedIds,
    baseData: true,
  });
  const declaredIds = new Set(existing.map((relation) => relation.toId));
  const missingIds = matchedIds.filter((id) => !declaredIds.has(id));
  for (let index = 0; index < missingIds.length; index += 1) {
    await addStixCoreRelationship(context, user, {
      fromId: platform.internal_id,
      toId: missingIds[index],
      relationship_type: RELATION_PROVIDES,
      description: 'Declared from log sources through the defense matrix log source mapping',
    });
  }
  const dataComponentsOfLogsources = await findByIdsChunked<BasicStoreEntity>(context, user, matchedIds, { type: ENTITY_TYPE_DATA_COMPONENT });
  return {
    created_count: missingIds.length,
    existing_count: matchedIds.length - missingIds.length,
    dataComponents: dataComponentsOfLogsources,
    unmatched_data_components: unmatched,
  };
};
// endregion

// region status
export const requestDefenseCoverageRecompute = async () => {
  await requestFullDefenseCoverageComputation();
  return true;
};

export const getDefenseCoverageStatus = async (context: AuthContext, user: AuthUser) => {
  const snapshot = await getDefenseSnapshot(context);
  const validationConnectors = await connectorsForEnrichment(context, user, ENTITY_TYPE_SECURITY_COVERAGE, true);
  return {
    computed_at: computedAtOf(snapshot),
    last_full_computation: await getLastFullComputation(),
    // Pending until the requested computation is done, not only until the manager picks the request up
    full_computation_requested: (await isFullComputationRequested()) || (await isFullComputationRunning()),
    validation_available: validationConnectors.length > 0,
  };
};
// endregion

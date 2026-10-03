import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { lockResources } from '../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../config/errors';
import type { DataEvent, SseEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/utils';
import { STIX_TYPE_RELATION } from '../schema/general';
import {
  RELATION_DEPLOYED_ON,
  RELATION_DETECTS,
  RELATION_HAS_COVERED,
  RELATION_INDICATES,
  RELATION_MITIGATES,
  RELATION_PROVIDES,
  RELATION_SUBTECHNIQUE_OF,
} from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_IDENTITY_SYSTEM } from '../schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../modules/securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../modules/securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { computeDefenseCoverage, findTechniquesOfSources } from '../modules/defenseCoverage/defenseCoverage-compute';
import {
  consumeFullComputationRequest,
  getLastFullComputation,
  requestFullDefenseCoverageComputation,
  setLastFullComputation,
} from '../modules/defenseCoverage/defenseCoverage-state';
import { addDefenseGapClosedCount } from './telemetryManager';
import type { AuthContext } from '../types/user';

const DEFENSE_COVERAGE_MANAGER_ID = 'DEFENSE_COVERAGE_MANAGER';
const DEFENSE_COVERAGE_MANAGER_LABEL = 'Defense coverage manager';
const DEFENSE_COVERAGE_MANAGER_CONTEXT = 'defense_coverage_manager';

const DEFENSE_COVERAGE_MANAGER_ENABLED = booleanConf('defense_coverage_manager:enabled', true);
const DEFENSE_COVERAGE_MANAGER_KEY = conf.get('defense_coverage_manager:lock_key') || 'defense_coverage_manager_lock';
const DEFENSE_COVERAGE_MANAGER_STREAM_KEY = conf.get('defense_coverage_manager:stream_lock_key') || 'defense_coverage_manager_stream_lock';
const DEFENSE_COVERAGE_COMPUTE_KEY = 'defense_coverage_compute_lock';
const SCHEDULE_TIME = conf.get('defense_coverage_manager:interval') || 300000; // 5 minutes
const FULL_COMPUTATION_INTERVAL = conf.get('defense_coverage_manager:full_computation_interval') || 86400000; // 1 day
const STREAM_BUFFER_TIME = conf.get('defense_coverage_manager:stream_buffer_time') || 10000;
const MAX_INCREMENTAL_TECHNIQUES = conf.get('defense_coverage_manager:max_incremental_techniques') || 300;
const COMPUTE_LOCK_RETRY_COUNT = 30;

// Deleting or merging one of these entities removes relationships without dedicated events: recompute everything.
const FULL_RECOMPUTE_ENTITY_TYPES = [
  ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_SECURITY_COVERAGE,
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  ENTITY_TYPE_ATTACK_PATTERN,
];
const TECHNIQUE_RELATIONSHIPS = [RELATION_DETECTS, RELATION_INDICATES, RELATION_MITIGATES, RELATION_HAS_COVERED, RELATION_SUBTECHNIQUE_OF];

export interface DefenseImpact {
  full: boolean;
  techniqueIds: Set<string>;
  dataComponentIds: Set<string>;
  ruleIds: Set<string>;
}

interface StixEventData {
  type: string;
  relationship_type?: string;
  extensions: Record<string, {
    id: string;
    type: string;
    source_ref?: string;
    source_type?: string;
    target_ref?: string;
    target_type?: string;
  }>;
}

/**
 * Impact of a batch of stream events on the stored coverage.
 */
export const collectDefenseImpact = (events: Array<SseEvent<DataEvent>>): DefenseImpact => {
  const impact: DefenseImpact = { full: false, techniqueIds: new Set(), dataComponentIds: new Set(), ruleIds: new Set() };
  events.forEach((event) => {
    const eventType = event.data.type;
    const data = event.data.data as unknown as StixEventData;
    const extension = data.extensions?.[STIX_EXT_OCTI];
    if (!extension) return;
    if (data.type === STIX_TYPE_RELATION) {
      const relationshipType = data.relationship_type ?? '';
      if (TECHNIQUE_RELATIONSHIPS.includes(relationshipType)) {
        if (extension.target_type === ENTITY_TYPE_ATTACK_PATTERN && extension.target_ref) impact.techniqueIds.add(extension.target_ref);
        if (relationshipType === RELATION_SUBTECHNIQUE_OF && extension.source_ref) impact.techniqueIds.add(extension.source_ref);
      } else if (relationshipType === RELATION_PROVIDES && extension.target_ref) {
        impact.dataComponentIds.add(extension.target_ref);
      } else if (relationshipType === RELATION_DEPLOYED_ON && extension.source_ref) {
        impact.ruleIds.add(extension.source_ref);
      }
      return;
    }
    if (eventType === EVENT_TYPE_MERGE) {
      if (FULL_RECOMPUTE_ENTITY_TYPES.includes(extension.type)) impact.full = true;
      return;
    }
    if (eventType === EVENT_TYPE_DELETE && FULL_RECOMPUTE_ENTITY_TYPES.includes(extension.type)) {
      impact.full = true;
      return;
    }
    if (extension.type === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM && eventType === EVENT_TYPE_CREATE) {
      // A new platform brings a new column of gaps
      impact.full = true;
      return;
    }
    if (extension.type === ENTITY_TYPE_ATTACK_PATTERN && (eventType === EVENT_TYPE_CREATE || eventType === EVENT_TYPE_UPDATE)) {
      impact.techniqueIds.add(extension.id);
      return;
    }
    if (extension.type === ENTITY_TYPE_INDICATOR && eventType === EVENT_TYPE_UPDATE) {
      // Pattern type, log source or revocation changes move a rule in or out of the detection layer
      impact.ruleIds.add(extension.id);
    }
  });
  return impact;
};

const runComputation = async (context: AuthContext, attackPatternIds?: string[]) => {
  let lock;
  try {
    lock = await lockResources([DEFENSE_COVERAGE_COMPUTE_KEY], { retryCount: COMPUTE_LOCK_RETRY_COUNT });
    const result = await computeDefenseCoverage(context, SYSTEM_USER, { attackPatternIds });
    await addDefenseGapClosedCount(result.closed_gaps);
    return result;
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Nightly full computation, also triggered on request (mapping change, platform creation or deletion, manual recompute).
 */
export const defenseCoverageCronHandler = async () => {
  const context = executionContext(DEFENSE_COVERAGE_MANAGER_CONTEXT);
  const lastFull = await getLastFullComputation();
  const requested = await consumeFullComputationRequest();
  const isDue = !lastFull || Date.now() - new Date(lastFull).getTime() >= FULL_COMPUTATION_INTERVAL;
  if (!isDue && !requested) {
    return;
  }
  const startedAt = new Date().toISOString();
  try {
    await runComputation(context);
    await setLastFullComputation(startedAt);
  } catch (e) {
    // Keep the request so the next run retries
    await requestFullDefenseCoverageComputation();
    throw e;
  }
};

export const defenseCoverageStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  if (streamEvents.length === 0) return;
  const context = executionContext(DEFENSE_COVERAGE_MANAGER_CONTEXT);
  const impact = collectDefenseImpact(streamEvents);
  if (impact.full) {
    await requestFullDefenseCoverageComputation();
    return;
  }
  const techniqueIds = new Set(impact.techniqueIds);
  const [fromDataComponents, fromRules] = await Promise.all([
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_DETECTS, Array.from(impact.dataComponentIds)),
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_INDICATES, Array.from(impact.ruleIds)),
  ]);
  fromDataComponents.forEach((id) => techniqueIds.add(id));
  fromRules.forEach((id) => techniqueIds.add(id));
  if (techniqueIds.size === 0) return;
  if (techniqueIds.size > MAX_INCREMENTAL_TECHNIQUES) {
    await requestFullDefenseCoverageComputation();
    return;
  }
  try {
    await runComputation(context, Array.from(techniqueIds));
  } catch (e: any) {
    // The next full computation will catch up with these changes
    await requestFullDefenseCoverageComputation();
    if (e?.name !== TYPE_LOCK_ERROR) {
      logApp.error('[OPENCTI-MODULE] Defense coverage incremental computation error', { cause: e, techniques: techniqueIds.size });
    }
  }
};

const DEFENSE_COVERAGE_MANAGER_DEFINITION: ManagerDefinition = {
  id: DEFENSE_COVERAGE_MANAGER_ID,
  label: DEFENSE_COVERAGE_MANAGER_LABEL,
  executionContext: DEFENSE_COVERAGE_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: defenseCoverageCronHandler,
    interval: SCHEDULE_TIME,
    lockKey: DEFENSE_COVERAGE_MANAGER_KEY,
    runOnStart: true,
  },
  streamSchedulerHandler: {
    handler: defenseCoverageStreamHandler,
    interval: SCHEDULE_TIME,
    lockKey: DEFENSE_COVERAGE_MANAGER_STREAM_KEY,
    streamOpts: { bufferTime: STREAM_BUFFER_TIME },
    streamProcessorStartFrom: () => 'live',
  },
  enabledByConfig: DEFENSE_COVERAGE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(DEFENSE_COVERAGE_MANAGER_DEFINITION);

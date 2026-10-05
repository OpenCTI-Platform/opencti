import type { DataEvent, SseEvent } from '../../types/event';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../database/utils';
import { STIX_TYPE_RELATION } from '../../schema/general';
import {
  RELATION_DEPLOYED_ON,
  RELATION_DETECTS,
  RELATION_HAS_COVERED,
  RELATION_INDICATES,
  RELATION_MITIGATES,
  RELATION_PROVIDES,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_USES,
} from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../schema/stixMetaObject';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { DEFENSE_THREAT_TYPES } from './defenseCoverage-types';

// Deleting or merging one of these entities removes relationships without dedicated events: recompute everything.
// Updating one of them can change who may see it as an evidence.
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
// Patch paths of the attributes deciding who may see an element (markings, organizations, authorized members)
const ACCESS_PATCH_PATH = /object_marking_refs|granted_refs|authorized_members|restricted_members/;

const isAccessUpdate = (event: SseEvent<DataEvent>) => {
  const patch = (event.data as unknown as { context?: { patch?: Array<{ path?: string }> } }).context?.patch ?? [];
  return patch.some((operation) => ACCESS_PATCH_PATH.test(operation.path ?? ''));
};

export interface DefenseImpact {
  full: boolean;
  techniqueIds: Set<string>;
  dataComponentIds: Set<string>;
  ruleIds: Set<string>;
  // Security coverage results whose covered techniques must be recomputed
  resultIds: Set<string>;
  // Courses of action whose mitigated techniques must be recomputed (a revocation withdraws the mitigation)
  mitigationIds: Set<string>;
  accessChanged: boolean;
  // The threat usages of the overlays changed: a uses relationship, or a threat created, removed or with a new access
  overlayChanged: boolean;
  // A threat or one of its relationships changed, which can move it in or out of the threats of a filtered scope
  threatsChanged: boolean;
  // A kill chain phase was created, renamed, reordered, merged or deleted: readers reload the tactics of the matrix
  phasesChanged: boolean;
}

interface StixEventData {
  type: string;
  relationship_type?: string;
  extensions?: Record<string, {
    id: string;
    type: string;
    source_ref?: string;
    source_type?: string;
    target_ref?: string;
    target_type?: string;
  }>;
}

/**
 * Impact of a batch of stream events on the stored coverage: techniques to recompute directly,
 * data components and rules whose techniques must be recomputed, or a full recomputation.
 */
export const collectDefenseImpact = (events: Array<SseEvent<DataEvent>>): DefenseImpact => {
  const impact: DefenseImpact = {
    full: false,
    techniqueIds: new Set(),
    dataComponentIds: new Set(),
    ruleIds: new Set(),
    resultIds: new Set(),
    mitigationIds: new Set(),
    accessChanged: false,
    overlayChanged: false,
    threatsChanged: false,
    phasesChanged: false,
  };
  events.forEach((event) => {
    const eventType = event.data.type;
    const data = event.data.data as unknown as StixEventData;
    const extension = data?.extensions?.[STIX_EXT_OCTI];
    if (!extension) return;
    if (data.type === STIX_TYPE_RELATION) {
      const relationshipType = data.relationship_type ?? '';
      if (DEFENSE_THREAT_TYPES.includes(extension.source_type ?? '') || DEFENSE_THREAT_TYPES.includes(extension.target_type ?? '')) {
        impact.threatsChanged = true;
      }
      if (relationshipType === RELATION_USES) {
        if (extension.target_type === ENTITY_TYPE_ATTACK_PATTERN) impact.overlayChanged = true;
      } else if (TECHNIQUE_RELATIONSHIPS.includes(relationshipType)) {
        if (extension.target_type === ENTITY_TYPE_ATTACK_PATTERN && extension.target_ref) impact.techniqueIds.add(extension.target_ref);
        if (relationshipType === RELATION_SUBTECHNIQUE_OF && extension.source_ref) impact.techniqueIds.add(extension.source_ref);
      } else if (relationshipType === RELATION_PROVIDES && extension.source_type === ENTITY_TYPE_IDENTITY_SYSTEM
        && (eventType === EVENT_TYPE_CREATE || eventType === EVENT_TYPE_DELETE)) {
        // A system is a defense platform while it provides telemetry: its first or last provides adds or removes a column of gaps
        impact.full = true;
      } else if (relationshipType === RELATION_PROVIDES && extension.target_ref) {
        impact.dataComponentIds.add(extension.target_ref);
      } else if (relationshipType === RELATION_DEPLOYED_ON && extension.source_ref) {
        impact.ruleIds.add(extension.source_ref);
      }
      return;
    }
    if (DEFENSE_THREAT_TYPES.includes(extension.type)) {
      impact.threatsChanged = true;
      if (eventType !== EVENT_TYPE_UPDATE || isAccessUpdate(event)) {
        impact.overlayChanged = true;
        return;
      }
    }
    if (extension.type === ENTITY_TYPE_KILL_CHAIN_PHASE) {
      impact.phasesChanged = true;
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
      return;
    }
    if (eventType === EVENT_TYPE_UPDATE && FULL_RECOMPUTE_ENTITY_TYPES.includes(extension.type)) {
      // A marking or organization change on an evidence changes who may see it: readers re-evaluate their access
      impact.accessChanged = true;
      if (extension.type === ENTITY_TYPE_DATA_COMPONENT) impact.dataComponentIds.add(extension.id);
      if (extension.type === ENTITY_TYPE_COURSE_OF_ACTION) impact.mitigationIds.add(extension.id);
      // A connector upsert of a result can change its date or its security coverage without touching has-covered
      if (extension.type === ENTITY_TYPE_SECURITY_COVERAGE_RESULT) impact.resultIds.add(extension.id);
    }
  });
  return impact;
};

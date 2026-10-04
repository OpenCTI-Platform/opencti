import type { AuthContext } from '../../types/user';
import { getEntitiesListFromCache } from '../../database/cache';
import { elCount } from '../../database/engine';
import {
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
} from '../../database/utils';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { TELEMETRY_MANAGER_USER } from '../../utils/access';
import { type BasicStoreEntityDecayRule, ENTITY_TYPE_DECAY_RULE } from '../decayRule/decayRule-types';
import { PROVENANCE_ENABLED } from './provenance-config';

export interface ProvenanceTelemetryGauges {
  setActiveKnowledgeDecayRulesCount: (n: number) => void;
  setProvenanceTrackedRelationshipsCount: (n: number) => void;
  setProvenanceCorroboratedRelationshipsCount: (n: number) => void;
  setProvenanceStaleKnowledgeCount: (n: number) => void;
  setProvenanceConflictingKnowledgeCount: (n: number) => void;
}

const provenanceFilter = (key: string, values: string[], operator = FilterOperator.Eq) => ({
  mode: FilterMode.And,
  filters: [{ key: [key], values, operator }],
  filterGroups: [],
});

/**
 * Provenance and knowledge freshness gauges. While provenance is switched off nothing is read
 * (neither the decay rule cache nor the indices) and every gauge stays at zero.
 */
export const fetchProvenanceTelemetry = async (context: AuthContext, gauges: ProvenanceTelemetryGauges, enabled = PROVENANCE_ENABLED) => {
  if (!enabled) {
    return;
  }
  const decayRules = await getEntitiesListFromCache<BasicStoreEntityDecayRule>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_DECAY_RULE);
  gauges.setActiveKnowledgeDecayRulesCount(decayRules.filter((rule) => rule.active && (rule.target_scope ?? 'indicator') !== 'indicator').length);
  const provenanceIndices = [READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS];
  const [trackedRelationships, corroboratedRelationships, staleKnowledge, conflictingKnowledge] = await Promise.all([
    elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, { filters: provenanceFilter('corroboration_count', [], FilterOperator.NotNil) }),
    elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, { filters: provenanceFilter('corroboration_count', ['2'], FilterOperator.Gte) }),
    elCount(context, TELEMETRY_MANAGER_USER, provenanceIndices, { filters: provenanceFilter('freshness_stale', ['true']) }),
    elCount(context, TELEMETRY_MANAGER_USER, provenanceIndices, { filters: provenanceFilter('has_conflicts', ['true']) }),
  ]);
  gauges.setProvenanceTrackedRelationshipsCount(trackedRelationships);
  gauges.setProvenanceCorroboratedRelationshipsCount(corroboratedRelationships);
  gauges.setProvenanceStaleKnowledgeCount(staleKnowledge);
  gauges.setProvenanceConflictingKnowledgeCount(conflictingKnowledge);
};

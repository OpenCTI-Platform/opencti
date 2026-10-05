import type { AuthContext, AuthUser } from '../../types/user';
import { elCount, elPaginate } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { FilterMode, OrderingMode } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import {
  type BasicStoreEntityKnowledgeHealthSnapshot,
  ENTITY_TYPE_CURATION_POLICY,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT,
  PROPOSAL_STATUS_OPEN,
} from './curation-types';
import { getCurationSettings } from './curation-settings';

export interface CurationTelemetryGauges {
  openProposals: number;
  enabledPolicies: number;
  healthScore: number;
  curationEnabled: boolean;
}

export const computeCurationTelemetryGauges = async (context: AuthContext, user: AuthUser): Promise<CurationTelemetryGauges> => {
  try {
    const [openProposals, enabledPolicies, snapshots, settings] = await Promise.all([
      elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_CURATION_PROPOSAL],
        filters: { mode: FilterMode.And, filters: [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN] }], filterGroups: [] },
      }),
      elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_CURATION_POLICY],
        filters: { mode: FilterMode.And, filters: [{ key: ['policy_enabled'], values: ['true'] }], filterGroups: [] },
      }),
      elPaginate<BasicStoreEntityKnowledgeHealthSnapshot>(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT],
        first: 1,
        orderBy: 'snapshot_date',
        orderMode: OrderingMode.Desc,
        connectionFormat: false,
      }) as Promise<BasicStoreEntityKnowledgeHealthSnapshot[]>,
      getCurationSettings(context),
    ]);
    return {
      openProposals,
      enabledPolicies,
      healthScore: snapshots[0]?.health_score ?? 0,
      curationEnabled: settings.curation_enabled,
    };
  } catch (error) {
    logApp.warn('[CURATION] Cannot compute curation telemetry gauges', { cause: error });
    return { openProposals: 0, enabledPolicies: 0, healthScore: 0, curationEnabled: false };
  }
};

import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { logApp } from '../../config/conf';
import { createEntity, createRelation } from '../../database/middleware';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { HUNT_MANAGER_USER } from '../../utils/access';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { type BasicStoreEntityHunt, RELATION_HUNT_TARGETS, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import type { BasicStoreEntityHuntRun } from './huntRun/huntRun-types';
import { truncate } from './hunt-utils';

const INCIDENT_SEVERITIES = ['low', 'medium', 'high', 'critical'];
export const HUNT_INCIDENT_RECOMMENDATION = 'Recommendation: Run Case Autopilot on this incident once the draft is validated, to investigate the hits and their attribution.';

export interface HuntIncidentProposal {
  name?: string | null;
  description?: string | null;
  severity?: string | null;
}

export const parseIncidentProposal = (proposal: string | null | undefined): HuntIncidentProposal | null => {
  if (!proposal) {
    return null;
  }
  try {
    const parsed = JSON.parse(proposal);
    return typeof parsed === 'object' && parsed !== null ? parsed as HuntIncidentProposal : null;
  } catch {
    return null;
  }
};

/**
 * The draft workspace an incident proposed by a hunt run is created in (draft-first: an analyst validates it into the
 * knowledge graph).
 */
export const createHuntIncidentWorkspace = async (context: AuthContext, hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun): Promise<string> => {
  const draft = await addDraftWorkspace(context, HUNT_MANAGER_USER, {
    name: truncate(`Hunt incident - ${hunt.name}`, 250),
    description: `Incident proposed by the hunt "${hunt.name}" (run ${run.internal_id}, ${run.hits_count ?? 0} hits). Validate the draft to create the incident.`,
  });
  return draft.id;
};

/**
 * Creates the Incident of a hunt run in its draft workspace. The incident inherits the hunt markings, author and
 * organizations, and is related to the hunt targets and techniques.
 */
export const createHuntIncidentInWorkspace = async (
  context: AuthContext,
  hunt: BasicStoreEntityHunt,
  run: BasicStoreEntityHuntRun,
  proposal: HuntIncidentProposal | null,
  draftId: string,
): Promise<string> => {
  const draftContext: AuthContext = { ...context, draft_context: draftId };
  const severity = proposal?.severity && INCIDENT_SEVERITIES.includes(proposal.severity) ? proposal.severity : 'medium';
  const name = proposal?.name?.trim() || `${hunt.name} - ${run.hits_count ?? 0} hits`;
  const summary = proposal?.description?.trim()
    || [
      `Hunt hypothesis: ${hunt.hypothesis ?? 'not provided'}`,
      `The hunt matched ${run.hits_count ?? 0} events (${run.distinct_entities ?? 0} distinct entities) between ${run.time_window_start} and ${run.time_window_end}.`,
    ].join('\n\n');
  // Hunts never investigate: the deeper look is the job of Case Autopilot, run by the analyst or a playbook
  const description = `${summary}\n\n${HUNT_INCIDENT_RECOMMENDATION}`;
  const incidentInput: Record<string, unknown> = {
    name: truncate(name, 250),
    description,
    incident_type: 'alert',
    severity,
    source: 'OpenCTI Hunts',
    first_seen: run.time_window_start,
    last_seen: run.time_window_end,
    objectMarking: hunt[RELATION_OBJECT_MARKING] ?? [],
    objectOrganization: hunt[RELATION_GRANTED_TO] ?? [],
  };
  if (hunt[RELATION_CREATED_BY]) {
    incidentInput.createdBy = hunt[RELATION_CREATED_BY];
  }
  const incident = await createEntity(draftContext, HUNT_MANAGER_USER, incidentInput, ENTITY_TYPE_INCIDENT, { bypassMandatoryAttributes: true }) as BasicStoreEntity;
  const relatedIds = [...(hunt[RELATION_HUNT_TARGETS] ?? []), ...(hunt[RELATION_HUNT_TECHNIQUES] ?? [])];
  for (let index = 0; index < relatedIds.length; index += 1) {
    try {
      await createRelation(draftContext, HUNT_MANAGER_USER, {
        fromId: incident.internal_id,
        toId: relatedIds[index],
        relationship_type: RELATION_RELATED_TO,
        objectMarking: hunt[RELATION_OBJECT_MARKING] ?? [],
      });
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt incident draft relation could not be created', { cause: error, huntId: hunt.internal_id, toId: relatedIds[index] });
    }
  }
  return incident.internal_id;
};

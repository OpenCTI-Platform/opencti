import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { logApp } from '../../config/conf';
import { createEntity, createRelation } from '../../database/middleware';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { HUNT_MANAGER_USER, MEMBER_ACCESS_RIGHT_EDIT } from '../../utils/access';
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
 * knowledge graph). The workspace is restricted to the organizations the run is shared with, if any, and its name and
 * description carry no detail of the hunt: draft workspaces are listed to every user with draft access, the markings
 * of the run only protect the incident inside.
 */
export const createHuntIncidentWorkspace = async (context: AuthContext, run: BasicStoreEntityHuntRun): Promise<string> => {
  const organizations = run[RELATION_GRANTED_TO] ?? [];
  const draft = await addDraftWorkspace(context, HUNT_MANAGER_USER, {
    name: `Hunt incident - run ${run.internal_id}`,
    description: 'Incident proposed by a hunt run. Validate the draft to create the incident.',
    ...(organizations.length > 0 ? { authorized_members: organizations.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_EDIT })) } : {}),
  });
  return draft.id;
};

/**
 * Creates the Incident of a hunt run in its draft workspace. The incident carries the markings and organizations of
 * the run (those of the hunt and of its security platform), the hunt author, and is related to the hunt targets and
 * techniques.
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
    objectMarking: run[RELATION_OBJECT_MARKING] ?? [],
    objectOrganization: run[RELATION_GRANTED_TO] ?? [],
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
        objectMarking: run[RELATION_OBJECT_MARKING] ?? [],
      });
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt incident draft relation could not be created', { cause: error, huntId: hunt.internal_id, toId: relatedIds[index] });
    }
  }
  return incident.internal_id;
};

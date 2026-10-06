import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { logApp } from '../../config/conf';
import { createEntity, createRelation, patchAttribute } from '../../database/middleware';
import { internalLoadById, topEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { HUNT_MANAGER_USER, MEMBER_ACCESS_RIGHT_EDIT, SYSTEM_USER } from '../../utils/access';
import { findByType as findStatusesByType } from '../../domain/status';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { DRAFT_STATUS_OPEN } from '../draftWorkspace/draftStatuses';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import { type BasicStoreEntityHunt, RELATION_HUNT_SOURCES, RELATION_HUNT_TARGETS, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, type HuntHit } from './huntRun/huntRun-types';
import { validateSigmaRule } from './hunt-sigma';
import { truncate } from './hunt-utils';

const INCIDENT_SEVERITIES = ['low', 'medium', 'high', 'critical'];
// Sigma levels as incident severities: an informational rule raises a low one
const SIGMA_LEVEL_SEVERITIES: Record<string, string> = { informational: 'low', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
const DESCRIPTION_HITS_MAX = 5;
const DESCRIPTION_TOP_VALUES = 5;
export const HUNT_INCIDENT_RECOMMENDATION = 'Recommendation: Run Case Autopilot on this incident once the draft is validated, to investigate the hits listed above, '
  + 'the observables and observed data it is related to, and their attribution.';

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

const topValues = (hits: HuntHit[], values: (hit: HuntHit) => (string | null | undefined)[]): string[] => {
  const counts = new Map<string, number>();
  hits.forEach((hit) => {
    new Set(values(hit)).forEach((value) => {
      if (typeof value === 'string' && value.length > 0) {
        counts.set(value, (counts.get(value) ?? 0) + 1);
      }
    });
  });
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, DESCRIPTION_TOP_VALUES)
    .map(([value, count]) => (count > 1 ? `${value} (${count})` : value));
};

const describeHit = (hit: HuntHit) => {
  const parts = [
    hit.timestamp ?? 'undated',
    hit.host ? `host ${hit.host}` : null,
    hit.user ? `user ${hit.user}` : null,
    hit.process ? `process ${hit.process}` : null,
    ...(hit.matched ?? []).map((match) => `${match.field}${match.value_preview ? ` = ${truncate(match.value_preview, 200)}` : ''}`),
  ];
  return `- ${parts.filter((part) => part !== null).join(', ')}`;
};

export interface HuntIncidentContent {
  name: string;
  description: string;
  severity: string;
  first_seen: string | undefined;
  last_seen: string | undefined;
}

/**
 * What the incident of a run says: the hypothesis of the hunt (its description without one), its rule and level, a
 * summary of the hits (dates, hosts, users, the matched field, the first ones) and the platform they come from. The
 * severity is the proposed one, else the level of the Sigma rule, else medium; the dates are those of the hits.
 */
export const buildHuntIncidentContent = (
  hunt: BasicStoreEntityHunt,
  run: BasicStoreEntityHuntRun,
  proposal: HuntIncidentProposal | null,
  platformName: string | null,
): HuntIncidentContent => {
  const sigma = hunt.sigma_rule ? validateSigmaRule(hunt.sigma_rule) : null;
  const levelSeverity = sigma?.level ? SIGMA_LEVEL_SEVERITIES[sigma.level] : undefined;
  const severity = proposal?.severity && INCIDENT_SEVERITIES.includes(proposal.severity) ? proposal.severity : (levelSeverity ?? 'medium');
  const hits = run.hits_sample ?? [];
  const firstSeen = run.first_hit_at ?? run.time_window_start;
  const lastSeen = run.last_hit_at ?? run.time_window_end;
  const hypothesis = hunt.hypothesis?.trim() || hunt.description?.trim();
  const sections: string[] = [];
  if (proposal?.description?.trim()) {
    sections.push(proposal.description.trim());
  } else if (hypothesis) {
    sections.push(`Hunt hypothesis: ${hypothesis}`);
  }
  if (sigma?.title) {
    sections.push(`Rule: ${sigma.title}${sigma.level ? ` (level ${sigma.level})` : ''}`);
  }
  const dated = run.first_hit_at ? `between ${firstSeen} and ${lastSeen}` : `in the time window ${run.time_window_start} - ${run.time_window_end}`;
  const platform = platformName ? ` on ${platformName}` : '';
  const known = run.hits_identified === true && (run.hits_recurring_count ?? 0) > 0
    ? ` ${run.hits_new_count ?? 0} of them were never seen before, ${run.hits_recurring_count} were seen by earlier runs.`
    : '';
  sections.push(`The hunt matched ${run.hits_count ?? 0} events (${run.distinct_entities ?? 0} distinct entities)${platform} ${dated}, in its run ${run.internal_id}.${known}`);
  if (hits.length > 0) {
    const facts = [
      ['Matched fields', topValues(hits, (hit) => (hit.matched ?? []).map((match) => match.field))],
      ['Hosts', topValues(hits, (hit) => [hit.host])],
      ['Users', topValues(hits, (hit) => [hit.user])],
      ['Processes', topValues(hits, (hit) => [hit.process])],
    ].filter(([, values]) => values.length > 0).map(([label, values]) => `${label}: ${(values as string[]).join(', ')}`);
    const shown = hits.slice(0, DESCRIPTION_HITS_MAX).map(describeHit);
    sections.push([...facts, `First hits (${shown.length} of ${run.hits_count ?? hits.length}):`, ...shown].join('\n'));
  } else {
    sections.push('The connector reported no single hit: the evidence of the hunt run lists the matched values.');
  }
  // Hunts never investigate: the deeper look is the job of Case Autopilot, run by the analyst or a playbook
  sections.push(HUNT_INCIDENT_RECOMMENDATION);
  return {
    name: truncate(proposal?.name?.trim() || `${hunt.name} - ${run.hits_count ?? 0} hits`, 250),
    description: sections.join('\n\n'),
    severity,
    first_seen: firstSeen,
    last_seen: lastSeen,
  };
};

/** What the incident of a run is related to: the hunt, its sources, targets and techniques, the platform, the hits. */
export const huntIncidentRelatedIds = (hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun): string[] => {
  return Array.from(new Set([
    hunt.internal_id,
    ...(hunt[RELATION_HUNT_SOURCES] ?? []),
    ...(hunt[RELATION_HUNT_TARGETS] ?? []),
    ...(hunt[RELATION_HUNT_TECHNIQUES] ?? []),
    ...(run.security_platform_id ? [run.security_platform_id] : []),
    ...(run.hit_observation_ids ?? []),
  ]));
};

/**
 * Creates the Incident of a hunt run in its draft workspace. The incident carries the markings and organizations of
 * the run (those of the hunt and of its security platform), the hunt author, and is related to what the run hunted
 * and found (huntIncidentRelatedIds).
 */
export const createHuntIncidentInWorkspace = async (
  context: AuthContext,
  hunt: BasicStoreEntityHunt,
  run: BasicStoreEntityHuntRun,
  proposal: HuntIncidentProposal | null,
  draftId: string,
): Promise<string> => {
  const draftContext: AuthContext = { ...context, draft_context: draftId };
  const platform = run.security_platform_id ? await internalLoadById<BasicStoreEntity>(context, HUNT_MANAGER_USER, run.security_platform_id) : null;
  const content = buildHuntIncidentContent(hunt, run, proposal, platform?.name ?? null);
  const incidentInput: Record<string, unknown> = {
    name: content.name,
    description: content.description,
    incident_type: 'alert',
    severity: content.severity,
    source: 'OpenCTI Hunts',
    first_seen: content.first_seen,
    last_seen: content.last_seen,
    objectMarking: run[RELATION_OBJECT_MARKING] ?? [],
    objectOrganization: run[RELATION_GRANTED_TO] ?? [],
  };
  if (hunt[RELATION_CREATED_BY]) {
    incidentInput.createdBy = hunt[RELATION_CREATED_BY];
  }
  const incident = await createEntity(draftContext, HUNT_MANAGER_USER, incidentInput, ENTITY_TYPE_INCIDENT, { bypassMandatoryAttributes: true }) as BasicStoreEntity;
  const relatedIds = huntIncidentRelatedIds(hunt, run);
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

/** An incident a later run of the hunt adds its hits to: in its draft while the draft is not validated, else in the knowledge. */
export interface OpenHuntIncident {
  incidentId: string;
  draftId: string | null;
}

type IncidentWithStatus = BasicStoreEntity & { x_opencti_workflow_id?: string | null };

/**
 * Whether an incident is closed: its status is the last one of the incident workflow (a workflow of one status, or no
 * status at all, never closes an incident).
 */
export const isHuntIncidentClosed = async (context: AuthContext, incident: IncidentWithStatus) => {
  if (!incident.x_opencti_workflow_id) {
    return false;
  }
  const statuses = (await findStatusesByType(context, SYSTEM_USER, ENTITY_TYPE_INCIDENT))
    .filter((status) => !status.scope || status.scope === 'GLOBAL')
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  return statuses.length > 1 && statuses[statuses.length - 1].internal_id === incident.x_opencti_workflow_id;
};

/**
 * The incident of a previous run of the hunt on the same security platform that is still open: its draft is not
 * validated yet, or it was validated and its status is not the last one of the incident workflow. Null when the latest
 * incident of the hunt on the platform is closed, deleted, or in a draft validated or deleted since.
 */
export const findOpenHuntIncident = async (context: AuthContext, run: BasicStoreEntityHuntRun): Promise<OpenHuntIncident | null> => {
  const [previous] = await topEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    first: 1,
    orderBy: 'completed_at',
    orderMode: OrderingMode.Desc,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_id'], values: [run.hunt_id] },
        run.security_platform_id
          ? { key: ['security_platform_id'], values: [run.security_platform_id] }
          : { key: ['security_platform_id'], values: [], operator: FilterOperator.Nil },
        { key: ['incident_id'], values: [], operator: FilterOperator.NotNil },
        { key: ['id'], values: [run.internal_id], operator: FilterOperator.NotEq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  if (!previous?.incident_id) {
    return null;
  }
  const draft = previous.draft_id
    ? await internalLoadById<BasicStoreEntity & { draft_status?: string }>(context, HUNT_MANAGER_USER, previous.draft_id, { type: ENTITY_TYPE_DRAFT_WORKSPACE })
    : null;
  const inDraft = previous.draft_id
    ? await internalLoadById<IncidentWithStatus>({ ...context, draft_context: previous.draft_id }, HUNT_MANAGER_USER, previous.incident_id, { type: ENTITY_TYPE_INCIDENT })
    : null;
  if (draft && draft.draft_status === DRAFT_STATUS_OPEN && inDraft) {
    return { incidentId: inDraft.internal_id, draftId: previous.draft_id ?? null };
  }
  // A validated draft published the incident under its standard id
  const live = await internalLoadById<IncidentWithStatus>(context, HUNT_MANAGER_USER, previous.incident_id, { type: ENTITY_TYPE_INCIDENT })
    ?? (inDraft ? await internalLoadById<IncidentWithStatus>(context, HUNT_MANAGER_USER, inDraft.standard_id, { type: ENTITY_TYPE_INCIDENT }) : null);
  if (!live || await isHuntIncidentClosed(context, live)) {
    return null;
  }
  return { incidentId: live.internal_id, draftId: null };
};

/**
 * Adds the hits of a run to an incident still open from a previous run of the hunt, in its draft when it has one: the
 * incident is related to the observed data and observables of the run, gets a note with the run summary, and its last
 * seen date moves to the last hit. Relations already there are kept.
 */
export const continueHuntIncident = async (context: AuthContext, hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun, open: OpenHuntIncident) => {
  const targetContext: AuthContext = open.draftId ? { ...context, draft_context: open.draftId } : context;
  const markings = run[RELATION_OBJECT_MARKING] ?? [];
  const relatedIds = Array.from(new Set(run.hit_observation_ids ?? []));
  for (let index = 0; index < relatedIds.length; index += 1) {
    try {
      await createRelation(targetContext, HUNT_MANAGER_USER, {
        fromId: open.incidentId,
        toId: relatedIds[index],
        relationship_type: RELATION_RELATED_TO,
        objectMarking: markings,
      });
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt incident relation could not be added', { cause: error, huntId: hunt.internal_id, toId: relatedIds[index] });
    }
  }
  const platform = run.security_platform_id ? await internalLoadById<BasicStoreEntity>(context, HUNT_MANAGER_USER, run.security_platform_id) : null;
  const content = buildHuntIncidentContent(hunt, run, null, platform?.name ?? null);
  const newHits = run.hits_new_count ?? run.hits_count ?? 0;
  await createEntity(targetContext, HUNT_MANAGER_USER, {
    attribute_abstract: truncate(`${hunt.name} - ${newHits} new hits in a later run`, 250),
    content: content.description,
    note_types: ['analysis'],
    objects: [open.incidentId],
    objectMarking: markings,
    ...(hunt[RELATION_CREATED_BY] ? { createdBy: hunt[RELATION_CREATED_BY] } : {}),
  }, ENTITY_TYPE_CONTAINER_NOTE);
  const incident = await internalLoadById<BasicStoreEntity & { last_seen?: string }>(targetContext, HUNT_MANAGER_USER, open.incidentId, { type: ENTITY_TYPE_INCIDENT });
  if (incident && content.last_seen && (!incident.last_seen || new Date(content.last_seen).getTime() > new Date(incident.last_seen).getTime())) {
    try {
      await patchAttribute(targetContext, HUNT_MANAGER_USER, open.incidentId, ENTITY_TYPE_INCIDENT, { last_seen: content.last_seen });
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt incident last seen date could not move', { cause: error, incidentId: open.incidentId });
    }
  }
};

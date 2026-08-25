import { BUS_TOPICS } from '../../config/conf';
import { notify } from '../../database/redis';
import { elRawCount, elRawSearch, ES_MAX_PAGINATION } from '../../database/engine';
import { createRelation, deleteElementById } from '../../database/middleware';
import { fullRelationsList } from '../../database/middleware-loader';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../../schema/general';
import {
  RELATION_ACCESSES_TO,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_CAPABILITY_IN_DRAFT,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
  RELATION_PARTICIPATE_TO,
} from '../../schema/internalRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import type { AuthContext } from '../../types/user';
import { BYPASS, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { userMergeBulkUpdate } from './userMerge-bulk';
import { type UserMergeProjectedRights, userMergeProjectRights, userMergeRightsDifference, type UserMergeRightsLabels, userMergeRightsNames } from './userMerge-rights';
import {
  type UserMergeHandler,
  type UserMergeHandlerContext,
  type UserMergeHandlerPlan,
  type UserMergePlannedChange,
  type UserMergeRightsAlert,
  USER_MERGE_TARGET_INDICES,
} from './userMerge-handler';
import {
  RESTRICTED_MEMBERS_ROW,
  type UserMergeRestrictedMember,
  userMergeRestrictedMembersOutcome,
  userMergeRestrictedMembersQuery,
  userMergeRestrictedMembersScript,
  userMergeRestrictionKey,
} from './userMerge-restrictedMembers';
import { UserMergeRightsStrategy } from './userMerge-types';

export const USER_MERGE_RIGHTS_HANDLER = 'user-rights';

/** A rights relation starting from the user being merged. */
interface UserRightsEdge {
  registerRow: string;
  relationshipType: string;
}

const MEMBERSHIP_EDGES: UserRightsEdge[] = [
  { registerRow: 'member-of.connections', relationshipType: RELATION_MEMBER_OF },
  { registerRow: 'participate-to.connections', relationshipType: RELATION_PARTICIPATE_TO },
];

/**
 * Rights relations the platform hangs off groups and roles, never off a user. They are listed
 * because `userAddRelation` accepts any internal relation whose source is a user, so legacy data
 * may carry them. They are removed with the source and never reproduced on the target: copying a
 * capability straight onto a user would grant a privilege the platform itself never grants.
 */
const DERIVED_EDGES: UserRightsEdge[] = [
  { registerRow: 'has-role.connections', relationshipType: RELATION_HAS_ROLE },
  { registerRow: 'has-capability.connections', relationshipType: RELATION_HAS_CAPABILITY },
  { registerRow: 'has-capability-in-draft.connections', relationshipType: RELATION_HAS_CAPABILITY_IN_DRAFT },
  { registerRow: 'accesses-to.connections', relationshipType: RELATION_ACCESSES_TO },
];

const AUTHORITIES_ROW = 'organization.authorized-authorities';
const AUTHORITIES_FIELD = 'authorized_authorities';
const FIELD_RESTRICTED_MEMBERS = 'restricted_members';

/**
 * The two figures every row reports. They answer different questions — what the source stops
 * holding, and what the target starts holding — and under STRICT the second is always zero.
 * Reporting it anyway is the point: the shape of the strategy is readable from the report.
 */
const REMOVED = 'removed from the source';
const GRANTED = 'granted to the target';

const edgePaths = [...MEMBERSHIP_EDGES, ...DERIVED_EDGES].map((edge) => `${edge.relationshipType}.connections`);
const authoritiesPath = `${ENTITY_TYPE_IDENTITY_ORGANIZATION}.${AUTHORITIES_FIELD}`;

interface EdgePlan {
  /** Relations to delete, all of the source's. */
  removed: { id: string; toId: string }[];
  /** Endpoints the target does not hold yet. Empty under STRICT. */
  granted: string[];
}

const readEdgePlan = async (
  context: AuthContext,
  edge: UserRightsEdge,
  sourceId: string,
  targetId: string,
  strategy: UserMergeRightsStrategy,
): Promise<EdgePlan> => {
  const sourceRelations = await fullRelationsList(context, SYSTEM_USER, edge.relationshipType, { fromId: sourceId });
  const removed = sourceRelations.map((relation) => ({ id: relation.internal_id, toId: relation.toId }));
  if (strategy === UserMergeRightsStrategy.Strict) {
    return { removed, granted: [] };
  }
  const targetRelations = await fullRelationsList(context, SYSTEM_USER, edge.relationshipType, { fromId: targetId });
  const held = targetRelations.map((relation) => relation.toId);
  // Deduplication belongs here rather than at write time: an endpoint the target already holds
  // is never granted twice, which is what makes replaying the merge a no-op.
  const granted = [...new Set(removed.map((relation) => relation.toId).filter((toId) => !held.includes(toId)))];
  return { removed, granted };
};

const readDerivedEdge = async (context: AuthContext, edge: UserRightsEdge, sourceId: string) => {
  const relations = await fullRelationsList(context, SYSTEM_USER, edge.relationshipType, { fromId: sourceId });
  return relations.map((relation) => relation.internal_id);
};

const derivedEdgeAlert = (edge: UserRightsEdge, count: number): UserMergeRightsAlert => ({
  register_row_id: edge.registerRow,
  kind: 'rights',
  message: `${count} ${edge.relationshipType} relation(s) start from the source user, which the platform does not create;`
    + ' they are removed and not reproduced on the target',
});

/** The target's rules as a comparable value: which restrictions, at which access right. */
const rulesOf = (members: UserMergeRestrictedMember[], targetId: string): string => {
  return members
    .filter((member) => member.id === targetId)
    .map((member) => `${userMergeRestrictionKey(member)}|${member.access_right}`)
    .sort()
    .join(';');
};

/**
 * Paginated on purpose: the count feeds an operator-facing figure, and a page-bounded scan would
 * silently under-report it on a platform where many elements list both users. Only a counter is
 * kept, so the loop stays flat in memory whatever the volume.
 *
 * A document counts as raised when the entries the target ends up with differ from the ones it
 * holds now — a stronger access right on a rule it already had, or a rule carried over from the
 * source under a restriction the target did not have.
 */
const readRestrictedMembersPlan = async (context: AuthContext, sourceId: string, targetId: string) => {
  const elements = await elRawCount({ index: USER_MERGE_TARGET_INDICES, body: { query: userMergeRestrictedMembersQuery(sourceId) } });
  if (elements === 0) {
    return { elements, raised: 0 };
  }
  let raised = 0;
  let searchAfter;
  let exhausted = false;
  while (!exhausted) {
    const overlapping = await elRawSearch(context, SYSTEM_USER, null, {
      index: USER_MERGE_TARGET_INDICES,
      size: ES_MAX_PAGINATION,
      _source: [FIELD_RESTRICTED_MEMBERS],
      body: {
        query: userMergeRestrictedMembersQuery(sourceId, targetId),
        sort: [{ 'internal_id.keyword': 'asc' }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
      },
    });
    const hits = overlapping.hits.hits as { _source: Record<string, UserMergeRestrictedMember[]>; sort: unknown[] }[];
    raised += hits.filter((hit) => {
      const members = hit._source[FIELD_RESTRICTED_MEMBERS] ?? [];
      const outcome = userMergeRestrictedMembersOutcome(members, sourceId, targetId);
      return rulesOf(members, targetId) !== rulesOf(outcome, targetId);
    }).length;
    exhausted = hits.length < ES_MAX_PAGINATION;
    searchAfter = exhausted ? undefined : hits[hits.length - 1].sort;
  }
  return { elements, raised };
};

const restrictedMembersAlert = (count: number): UserMergeRightsAlert => ({
  register_row_id: RESTRICTED_MEMBERS_ROW,
  kind: 'rights',
  message: `${count} element(s) list both users as authorized members and the target's own access changes;`
    + ' entries sharing a group restriction collapse into one keeping the strongest access right, the others are carried over as they are',
});

/**
 * Authorized member entries are transferred whatever the strategy, so the target ends up
 * managing elements it may not be allowed to manage. The merge is refused until the operator
 * says so: the alternative is a silent transfer to a user who cannot see what they now hold.
 */
const managementCapabilityAlert = (count: number): UserMergeRightsAlert => ({
  register_row_id: RESTRICTED_MEMBERS_ROW,
  kind: 'rights',
  message: `${count} element(s) list the source user as an authorized member and move to a target user without the ${KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS} capability`,
  blocking: true,
});

const rightsGapAlerts = (
  source: UserMergeProjectedRights,
  target: UserMergeProjectedRights,
  strategy: UserMergeRightsStrategy,
  labels: UserMergeRightsLabels,
): UserMergeRightsAlert[] => {
  const projected = userMergeProjectRights(source, target, strategy);
  const alerts: UserMergeRightsAlert[] = [];
  const gainedMarkings = userMergeRightsDifference(projected.markings, target.markings);
  const lostMarkings = userMergeRightsDifference(source.markings, projected.markings);
  const gainedOrganizations = userMergeRightsDifference(projected.organizations, target.organizations);
  const lostOrganizations = userMergeRightsDifference(source.organizations, projected.organizations);
  if (gainedMarkings.length > 0) {
    alerts.push({ register_row_id: MEMBERSHIP_EDGES[0].registerRow, kind: 'marking', message: `the target user gains ${userMergeRightsNames(labels, gainedMarkings)}` });
  }
  if (lostMarkings.length > 0) {
    alerts.push({ register_row_id: MEMBERSHIP_EDGES[0].registerRow, kind: 'marking', message: `${userMergeRightsNames(labels, lostMarkings)} were reachable through the source user and no longer are` });
  }
  if (gainedOrganizations.length > 0) {
    alerts.push({ register_row_id: MEMBERSHIP_EDGES[1].registerRow, kind: 'organization', message: `the target user joins ${userMergeRightsNames(labels, gainedOrganizations)}` });
  }
  if (lostOrganizations.length > 0) {
    alerts.push({ register_row_id: MEMBERSHIP_EDGES[1].registerRow, kind: 'organization', message: `${userMergeRightsNames(labels, lostOrganizations)} were reachable through the source user and no longer are` });
  }
  return alerts;
};

const authoritiesQuery = (sourceId: string, withoutTargetId?: string): Record<string, unknown> => ({
  bool: {
    must: [
      { term: { [`${AUTHORITIES_FIELD}.keyword`]: sourceId } },
      { terms: { 'entity_type.keyword': [ENTITY_TYPE_IDENTITY_ORGANIZATION] } },
    ],
    ...(withoutTargetId ? { must_not: [{ term: { [`${AUTHORITIES_FIELD}.keyword`]: withoutTargetId } }] } : {}),
  },
});

/**
 * Organization administration is stored on the organization, not on the user: the user's
 * `administrated_organizations` is recomputed at session build from this list. Rewriting it is
 * therefore the whole of the change, and a plain field rewrite is enough — unlike the relations,
 * nothing denormalizes it onto a second document.
 *
 * The field is also carried by feeds, collections and background tasks, where it holds
 * capability names rather than user ids. The query is scoped to organizations for that reason.
 */
const readAuthoritiesPlan = async (sourceId: string, targetId: string, strategy: UserMergeRightsStrategy) => {
  const removed = await elRawCount({ index: USER_MERGE_TARGET_INDICES, body: { query: authoritiesQuery(sourceId) } });
  if (strategy === UserMergeRightsStrategy.Strict) {
    return { removed, granted: 0 };
  }
  const granted = await elRawCount({ index: USER_MERGE_TARGET_INDICES, body: { query: authoritiesQuery(sourceId, targetId) } });
  return { removed, granted };
};

const authoritiesScript = (sourceId: string, targetId: string, strategy: UserMergeRightsStrategy) => ({
  source: `if (ctx._source.${AUTHORITIES_FIELD} != null && ctx._source.${AUTHORITIES_FIELD}.contains(params.source)) {`
    + ` ctx._source.${AUTHORITIES_FIELD}.removeIf(authority -> authority.equals(params.source));`
    + ` if (params.grant && !ctx._source.${AUTHORITIES_FIELD}.contains(params.target)) { ctx._source.${AUTHORITIES_FIELD}.add(params.target); }`
    + ' }',
  lang: 'painless',
  params: { source: sourceId, target: targetId, grant: strategy === UserMergeRightsStrategy.Union },
});

/**
 * Merges what the source user is entitled to into the target.
 *
 * Only `member-of` and `participate-to` actually start from a user; the other rights relations
 * hang off groups and roles, and are removed rather than transferred when found on a user.
 *
 * Relations go through the domain layer rather than a bulk rewrite: they are denormalized onto
 * both endpoints as `rel_<type>`, and a raw index write would leave those arrays describing a
 * membership that no longer exists.
 */
export const userMergeRightsHandler: UserMergeHandler = {
  identifier: USER_MERGE_RIGHTS_HANDLER,
  covers: [...MEMBERSHIP_EDGES.map((edge) => edge.registerRow), ...DERIVED_EDGES.map((edge) => edge.registerRow), AUTHORITIES_ROW, RESTRICTED_MEMBERS_ROW],
  reads: [...edgePaths, authoritiesPath, FIELD_RESTRICTED_MEMBERS],
  writes: [...edgePaths, authoritiesPath, FIELD_RESTRICTED_MEMBERS],
  compute: async ({ context, sourceId, targetId, options, rights }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    for (let i = 0; i < MEMBERSHIP_EDGES.length; i += 1) {
      const edge = MEMBERSHIP_EDGES[i];
      const plan = await readEdgePlan(context, edge, sourceId, targetId, options.rightsStrategy);
      changes.push({ register_row_id: edge.registerRow, entity_type: edge.relationshipType, count: plan.removed.length, exact: true, detail: REMOVED });
      changes.push({ register_row_id: edge.registerRow, entity_type: edge.relationshipType, count: plan.granted.length, exact: true, detail: GRANTED });
    }
    for (let i = 0; i < DERIVED_EDGES.length; i += 1) {
      const edge = DERIVED_EDGES[i];
      const relations = await readDerivedEdge(context, edge, sourceId);
      changes.push({ register_row_id: edge.registerRow, entity_type: edge.relationshipType, count: relations.length, exact: true, detail: REMOVED });
      if (relations.length > 0) {
        alerts.push(derivedEdgeAlert(edge, relations.length));
      }
    }
    const authorities = await readAuthoritiesPlan(sourceId, targetId, options.rightsStrategy);
    changes.push({ register_row_id: AUTHORITIES_ROW, entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, count: authorities.removed, exact: true, detail: REMOVED });
    changes.push({ register_row_id: AUTHORITIES_ROW, entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, count: authorities.granted, exact: true, detail: GRANTED });
    const restrictedMembers = await readRestrictedMembersPlan(context, sourceId, targetId);
    changes.push({ register_row_id: RESTRICTED_MEMBERS_ROW, entity_type: '*', count: restrictedMembers.elements, exact: true, detail: 'transferred to the target' });
    if (restrictedMembers.raised > 0) {
      alerts.push(restrictedMembersAlert(restrictedMembers.raised));
    }
    alerts.push(...rightsGapAlerts(rights.source, rights.target, options.rightsStrategy, rights.labels));
    const canManage = rights.target.capabilities.includes(BYPASS) || rights.target.capabilities.includes(KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS);
    if (restrictedMembers.elements > 0 && !canManage) {
      alerts.push(managementCapabilityAlert(restrictedMembers.elements));
    }
    return { handler: USER_MERGE_RIGHTS_HANDLER, changes, alerts };
  },
  apply: async ({ context, sourceId, targetId, options, sourceUser, targetUser }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    let updated = 0;
    for (let i = 0; i < MEMBERSHIP_EDGES.length; i += 1) {
      const edge = MEMBERSHIP_EDGES[i];
      const edgePlan = await readEdgePlan(context, edge, sourceId, targetId, options.rightsStrategy);
      for (let granted = 0; granted < edgePlan.granted.length; granted += 1) {
        await createRelation(context, SYSTEM_USER, { fromId: targetId, toId: edgePlan.granted[granted], relationship_type: edge.relationshipType });
        updated += 1;
      }
      for (let removed = 0; removed < edgePlan.removed.length; removed += 1) {
        await deleteElementById(context, SYSTEM_USER, edgePlan.removed[removed].id, ABSTRACT_INTERNAL_RELATIONSHIP);
        updated += 1;
      }
    }
    for (let i = 0; i < DERIVED_EDGES.length; i += 1) {
      const edge = DERIVED_EDGES[i];
      const relations = await readDerivedEdge(context, edge, sourceId);
      for (let removed = 0; removed < relations.length; removed += 1) {
        await deleteElementById(context, SYSTEM_USER, relations[removed], ABSTRACT_INTERNAL_RELATIONSHIP);
        updated += 1;
      }
    }
    const authoritiesPlanned = plan.changes.some((change) => change.register_row_id === AUTHORITIES_ROW && change.detail === REMOVED && change.count > 0);
    if (authoritiesPlanned) {
      const result = await userMergeBulkUpdate(
        `${USER_MERGE_RIGHTS_HANDLER}:${AUTHORITIES_ROW}`,
        USER_MERGE_TARGET_INDICES,
        { query: authoritiesQuery(sourceId), script: authoritiesScript(sourceId, targetId, options.rightsStrategy) },
      );
      updated += result.updated;
    }
    const restrictedPlanned = plan.changes.some((change) => change.register_row_id === RESTRICTED_MEMBERS_ROW && change.count > 0);
    if (restrictedPlanned) {
      const result = await userMergeBulkUpdate(
        `${USER_MERGE_RIGHTS_HANDLER}:${RESTRICTED_MEMBERS_ROW}`,
        USER_MERGE_TARGET_INDICES,
        { query: userMergeRestrictedMembersQuery(sourceId), script: userMergeRestrictedMembersScript(sourceId, targetId) },
      );
      updated += result.updated;
    }
    // Memberships and organization authorities are written through the store, which does not
    // notify: the domain helpers do it themselves, and this handler bypasses them. Without it
    // `buildCompleteUsers` keeps serving the pre-merge groups, markings and capabilities from
    // the cache — on this node until it restarts, and on every other node of a cluster for good.
    if (updated > 0) {
      await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, [sourceUser, targetUser], SYSTEM_USER);
    }
    return updated;
  },
};

import { authorizedMembers } from '../../schema/attribute-definition';
import { ACCESS_RIGHT_ORDER, userMergeStrongestAccessRight } from './userMerge-rights';

export const RESTRICTED_MEMBERS_ROW = 'authorized-members.restricted-members';

const FIELD = authorizedMembers.name;

/** One entry of the `restricted_members` array. */
export interface UserMergeRestrictedMember {
  id: string;
  access_right: string;
  groups_restriction_ids?: string[];
}

const listedAs = (userId: string) => ({
  nested: { path: FIELD, query: { term: { [`${FIELD}.id.keyword`]: userId } } },
});

/**
 * Elements listing the given user as an authorized member. `restricted_members` is mapped as a
 * nested type, so a plain term on the sub-field would match a document where the id and the
 * access right come from two different entries.
 */
export const userMergeRestrictedMembersQuery = (userId: string, alsoListing?: string): Record<string, unknown> => ({
  bool: { must: alsoListing ? [listedAs(userId), listedAs(alsoListing)] : [listedAs(userId)] },
});

/** Entries with the same restriction are the same rule; the order inside the list is irrelevant. */
export const userMergeRestrictionKey = (member: UserMergeRestrictedMember): string => {
  return [...(member.groups_restriction_ids ?? [])].sort().join(',');
};

/**
 * What the whole list becomes once the merge is applied.
 *
 * The script below implements the same rule; this is the readable statement of it, and what the
 * dry-run uses to tell whether the target's own access is about to change. A member can appear
 * several times under different restrictions, so each source entry is carried over on its own and
 * only meets a target entry sharing its restriction — where the strongest access right wins.
 */
export const userMergeRestrictedMembersOutcome = (
  members: UserMergeRestrictedMember[],
  sourceId: string,
  targetId: string,
): UserMergeRestrictedMember[] => {
  const kept: UserMergeRestrictedMember[] = [];
  const byRestriction = new Map<string, UserMergeRestrictedMember>();
  members.filter((member) => member.id !== sourceId).forEach((member) => {
    const copy = { ...member };
    kept.push(copy);
    if (member.id === targetId) {
      byRestriction.set(userMergeRestrictionKey(member), copy);
    }
  });
  members.filter((member) => member.id === sourceId).forEach((source) => {
    const key = userMergeRestrictionKey(source);
    const existing = byRestriction.get(key);
    if (existing) {
      existing.access_right = userMergeStrongestAccessRight(source.access_right, existing.access_right);
      return;
    }
    const moved = { ...source, id: targetId };
    kept.push(moved);
    byRestriction.set(key, moved);
  });
  return kept;
};

/**
 * Re-points the source entries to the target, collapsing only the ones the target already holds
 * under the same restriction.
 *
 * A member can legitimately appear several times with different `groups_restriction_ids`:
 * `sanitizeAuthorizedMembers` keeps them as separate rules, and `getExplicitUserAccessRight`
 * evaluates every rule the reader satisfies. Each source entry therefore has to be carried over
 * on its own — folding them all into one would either drop rules or turn a restricted grant into
 * an unrestricted one. Two entries meet only when their restriction is identical, and then the
 * strongest access right wins, because an array cannot hold the same member twice.
 */
export const userMergeRestrictedMembersScript = (sourceId: string, targetId: string) => ({
  source: 'String restrictionKey(def member) {'
    + ' def groups = member.groups_restriction_ids;'
    + ' if (groups == null || groups.isEmpty()) { return ""; }'
    + ' def sorted = new ArrayList(groups); Collections.sort(sorted); return String.join(",", sorted);'
    + ' }'
    + ` def members = ctx._source.${FIELD};`
    + ' if (members == null) { return; }'
    + ' def sources = new ArrayList(); def targets = new HashMap();'
    + ' for (member in members) {'
    + ' if (member.id == params.source) { sources.add(member); }'
    + ' else if (member.id == params.target) { targets.put(restrictionKey(member), member); }'
    + ' }'
    + ' if (sources.isEmpty()) { return; }'
    + ' for (source in sources) {'
    + ' def key = restrictionKey(source);'
    + ' def target = targets.get(key);'
    + ' if (target == null) {'
    + ' source.id = params.target; targets.put(key, source);'
    + ' } else if (params.order.indexOf(source.access_right) > params.order.indexOf(target.access_right)) {'
    + ' target.access_right = source.access_right;'
    + ' }'
    + ' }'
    // Only the entries that found a target to collapse into still carry the source id: the
    // re-pointed ones were rewritten in place above.
    + ' members.removeIf(member -> member.id == params.source);',
  lang: 'painless',
  params: { source: sourceId, target: targetId, order: ACCESS_RIGHT_ORDER },
});

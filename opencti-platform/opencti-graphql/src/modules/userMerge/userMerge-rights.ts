import type { AuthUser } from '../../types/user';
import { MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_USE, MEMBER_ACCESS_RIGHT_VIEW } from '../../utils/access';
import { UserMergeRightsStrategy } from './userMerge-types';

/**
 * The rights the target holds once the merge is applied.
 *
 * Markings and organizations are held as internal ids, never as labels. A marking definition is
 * only unique together with its definition_type (`schema/identifier.js`), so two distinct
 * markings can carry the same text; set operations on labels would collapse them and a real
 * widening would go unreported by the blocking alerts. Capabilities are held by name because
 * that is the identifier the access checks themselves compare.
 *
 * Every handler computes before any handler writes, so a handler asking the platform what the
 * target can access only ever gets the pre-merge answer. Anything that depends on the outcome
 * has to be derived from the strategy instead of observed, which is what this projection is.
 */
export interface UserMergeProjectedRights {
  markings: string[];
  organizations: string[];
  capabilities: string[];
  /**
   * Groups are a right of their own, not only a way to hold the ones above: `computeUserMemberAccessIds`
   * matches authorized member entries on the user id, its organizations and its groups, so a group
   * gained by the target opens every element granted to that group.
   */
  groups: string[];
}

/** Identifier to display name, carried beside the sets so reports stay readable. */
export type UserMergeRightsLabels = Record<string, string>;

interface IdentifiedRight { internal_id?: string; id?: string; name?: string; definition?: string }

const identifiersOf = (values: IdentifiedRight[] | undefined): string[] => {
  return (values ?? []).map((value) => value.internal_id ?? value.id ?? '').filter((value) => value !== '');
};

const namesOf = (values: { name?: string }[] | undefined): string[] => {
  return (values ?? []).map((value) => value.name ?? '').filter((value) => value !== '');
};

const union = (left: string[], right: string[]): string[] => [...left, ...right.filter((value) => !left.includes(value))];

export const userMergeRightsOf = (user: AuthUser): UserMergeProjectedRights => ({
  markings: identifiersOf(user.allowed_marking),
  organizations: identifiersOf(user.organizations),
  capabilities: namesOf(user.capabilities),
  groups: identifiersOf(user.groups),
});

/** Collected from both users, since an alert names rights either of them holds. */
export const userMergeRightsLabels = (...users: AuthUser[]): UserMergeRightsLabels => {
  const labels: UserMergeRightsLabels = {};
  users.forEach((user) => {
    [...(user.allowed_marking ?? []), ...(user.organizations ?? []), ...(user.groups ?? [])].forEach((right: IdentifiedRight) => {
      const identifier = right.internal_id ?? right.id;
      if (identifier) {
        labels[identifier] = right.definition ?? right.name ?? identifier;
      }
    });
  });
  return labels;
};

export const userMergeRightsNames = (labels: UserMergeRightsLabels, identifiers: string[]): string => {
  return identifiers.map((identifier) => labels[identifier] ?? identifier).join(', ');
};

/**
 * What the target ends up with.
 *
 * STRICT keeps the target as it is and drops the source's rights; UNION adds the source's on
 * top. The projection is deliberately expressed on the resolved sets rather than on the
 * relations, because that is the level the access checks read: joining a group brings its
 * roles, its capabilities and the whole lower half of every marking family it grants.
 */
export const userMergeProjectRights = (
  source: UserMergeProjectedRights,
  target: UserMergeProjectedRights,
  strategy: UserMergeRightsStrategy,
): UserMergeProjectedRights => {
  if (strategy === UserMergeRightsStrategy.Strict) {
    return target;
  }
  return {
    markings: union(target.markings, source.markings),
    organizations: union(target.organizations, source.organizations),
    capabilities: union(target.capabilities, source.capabilities),
    groups: union(target.groups, source.groups),
  };
};

export const userMergeRightsDifference = (left: string[], right: string[]): string[] => {
  return left.filter((value) => !right.includes(value));
};

/**
 * Authorized member access levels, weakest first. An entry naming both users has to collapse
 * into one, and collapsing to anything but the strongest of the two would silently demote an
 * access the merge was not asked to change.
 */
const ACCESS_RIGHT_ORDER = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_USE, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];

export const userMergeStrongestAccessRight = (left: string, right: string): string => {
  return ACCESS_RIGHT_ORDER.indexOf(left) >= ACCESS_RIGHT_ORDER.indexOf(right) ? left : right;
};

/**
 * Group restrictions narrow an authorized member entry: the reader must belong to every listed
 * group. Two entries collapsing into one keep the intersection, which is the only combination
 * that grants neither more nor less than the two entries did separately.
 */
export const userMergeMergedGroupsRestriction = (left: string[] | undefined, right: string[] | undefined): string[] => {
  const leftGroups = left ?? [];
  const rightGroups = right ?? [];
  if (leftGroups.length === 0 || rightGroups.length === 0) {
    return [];
  }
  return leftGroups.filter((group) => rightGroups.includes(group));
};

import { describe, expect, it } from 'vitest';
import {
  type UserMergeProjectedRights,
  userMergeProjectRights,
  userMergeRightsDifference,
  userMergeRightsLabels,
  userMergeRightsNames,
  userMergeRightsOf,
  userMergeStrongestAccessRight,
} from '../../../../src/modules/userMerge/userMerge-rights';
import { userMergeRestrictedMembersOutcome, userMergeRestrictedMembersQuery } from '../../../../src/modules/userMerge/userMerge-restrictedMembers';
import { UserMergeRightsStrategy } from '../../../../src/modules/userMerge/userMerge-types';
import type { AuthUser } from '../../../../src/types/user';

const source: UserMergeProjectedRights = {
  markings: ['marking-red', 'marking-amber'],
  organizations: ['organization-filigran'],
  capabilities: ['KNOWLEDGE'],
  groups: ['group-analysts'],
};

const target: UserMergeProjectedRights = {
  markings: ['marking-green'],
  organizations: ['organization-anssi'],
  capabilities: ['KNOWLEDGE', 'SETTINGS'],
  groups: ['group-readers'],
};

describe('User merge rights projection', () => {
  it('should keep the target untouched under the strict strategy', () => {
    expect(userMergeProjectRights(source, target, UserMergeRightsStrategy.Strict)).toEqual(target);
  });

  it('should add the source rights on top of the target under the union strategy', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Union);
    expect(projected.markings).toEqual(['marking-green', 'marking-red', 'marking-amber']);
    expect(projected.organizations).toEqual(['organization-anssi', 'organization-filigran']);
  });

  it('should never duplicate a right held by both users', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Union);
    expect(projected.capabilities).toEqual(['KNOWLEDGE', 'SETTINGS']);
  });

  it('should never take anything away from the target', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Union);
    expect(userMergeRightsDifference(target.markings, projected.markings)).toEqual([]);
  });

  it('should read the resolved rights of a user by identifier', () => {
    const user = {
      allowed_marking: [{ internal_id: 'marking-id', definition: 'TLP:RED' }],
      organizations: [{ internal_id: 'organization-id', name: 'Filigran' }],
      capabilities: [{ internal_id: 'capability-id', name: 'KNOWLEDGE' }],
      groups: [{ internal_id: 'group-id', name: 'Analysts' }],
    } as unknown as AuthUser;
    expect(userMergeRightsOf(user)).toEqual({ markings: ['marking-id'], organizations: ['organization-id'], capabilities: ['KNOWLEDGE'], groups: ['group-id'] });
  });

  it('should tolerate a user holding none of the resolved sets', () => {
    expect(userMergeRightsOf({} as AuthUser)).toEqual({ markings: [], organizations: [], capabilities: [], groups: [] });
  });
});

describe('User merge rights labels', () => {
  const user = {
    allowed_marking: [{ internal_id: 'marking-id', definition: 'TLP:RED' }],
    organizations: [{ internal_id: 'organization-id', name: 'Filigran' }],
    capabilities: [{ internal_id: 'capability-id', name: 'KNOWLEDGE' }],
    groups: [{ internal_id: 'group-id', name: 'Analysts' }],
  } as unknown as AuthUser;

  it('should name an identifier from the users involved in the merge', () => {
    const labels = userMergeRightsLabels(user);
    expect(userMergeRightsNames(labels, ['marking-id', 'organization-id', 'group-id'])).toEqual('TLP:RED, Filigran, Analysts');
  });

  it('should fall back on the identifier when nothing names it', () => {
    expect(userMergeRightsNames(userMergeRightsLabels(user), ['unknown-id'])).toEqual('unknown-id');
  });
});

describe('User merge authorized member collapse', () => {
  it('should keep the strongest of the two access rights', () => {
    expect(userMergeStrongestAccessRight('view', 'admin')).toEqual('admin');
    expect(userMergeStrongestAccessRight('edit', 'use')).toEqual('edit');
  });

  it('should re-point a source entry the target does not hold', () => {
    const outcome = userMergeRestrictedMembersOutcome(
      [{ id: 'source-id', access_right: 'admin', groups_restriction_ids: ['a'] }],
      'source-id',
      'target-id',
    );
    expect(outcome).toEqual([{ id: 'target-id', access_right: 'admin', groups_restriction_ids: ['a'] }]);
  });

  it('should collapse two entries sharing the same restriction, keeping the strongest right', () => {
    const outcome = userMergeRestrictedMembersOutcome(
      [
        { id: 'target-id', access_right: 'view', groups_restriction_ids: ['b', 'a'] },
        { id: 'source-id', access_right: 'admin', groups_restriction_ids: ['a', 'b'] },
      ],
      'source-id',
      'target-id',
    );
    expect(outcome).toEqual([{ id: 'target-id', access_right: 'admin', groups_restriction_ids: ['b', 'a'] }]);
  });

  it('should keep the source rules the target does not already hold as separate rules', () => {
    const outcome = userMergeRestrictedMembersOutcome(
      [
        { id: 'target-id', access_right: 'view', groups_restriction_ids: ['a'] },
        { id: 'source-id', access_right: 'admin', groups_restriction_ids: ['a'] },
        { id: 'source-id', access_right: 'edit', groups_restriction_ids: ['c'] },
        { id: 'source-id', access_right: 'use' },
      ],
      'source-id',
      'target-id',
    );
    expect(outcome).toEqual([
      { id: 'target-id', access_right: 'admin', groups_restriction_ids: ['a'] },
      { id: 'target-id', access_right: 'edit', groups_restriction_ids: ['c'] },
      { id: 'target-id', access_right: 'use' },
    ]);
  });

  it('should never turn a restricted grant into an unrestricted one', () => {
    const outcome = userMergeRestrictedMembersOutcome(
      [
        { id: 'target-id', access_right: 'view', groups_restriction_ids: ['b'] },
        { id: 'source-id', access_right: 'admin', groups_restriction_ids: ['a'] },
      ],
      'source-id',
      'target-id',
    );
    expect(outcome.every((member) => (member.groups_restriction_ids ?? []).length > 0)).toEqual(true);
  });

  it('should leave the other members alone', () => {
    const outcome = userMergeRestrictedMembersOutcome(
      [{ id: 'other-id', access_right: 'view' }, { id: 'source-id', access_right: 'admin' }],
      'source-id',
      'target-id',
    );
    expect(outcome).toEqual([{ id: 'other-id', access_right: 'view' }, { id: 'target-id', access_right: 'admin' }]);
  });

  it('should be a no-op on a list holding no source entry', () => {
    const members = [{ id: 'target-id', access_right: 'admin', groups_restriction_ids: ['a'] }];
    expect(userMergeRestrictedMembersOutcome(members, 'source-id', 'target-id')).toEqual(members);
  });

  it('should query the authorized members as a nested field', () => {
    const query = userMergeRestrictedMembersQuery('source-id') as { bool: { must: Record<string, any>[] } };
    expect(query.bool.must).toHaveLength(1);
    expect(query.bool.must[0].nested.path).toEqual('restricted_members');
    expect(query.bool.must[0].nested.query.term['restricted_members.id.keyword']).toEqual('source-id');
  });

  it('should require both users to be listed when asked for the overlap', () => {
    const query = userMergeRestrictedMembersQuery('source-id', 'target-id') as { bool: { must: Record<string, any>[] } };
    expect(query.bool.must).toHaveLength(2);
    expect(query.bool.must[1].nested.query.term['restricted_members.id.keyword']).toEqual('target-id');
  });
});

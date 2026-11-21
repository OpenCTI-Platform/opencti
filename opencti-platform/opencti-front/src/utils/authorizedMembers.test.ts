import { describe, it, expect } from 'vitest';
import { AccessRight, AuthorizedMemberOption, authorizedMembersToInput } from './authorizedMembers';

const member = (value: string, accessRight: AccessRight, groups: string[] = []): AuthorizedMemberOption => ({
  label: value,
  value,
  type: 'Organization',
  accessRight,
  groupsRestriction: groups.map((group) => ({ label: group, value: group })),
});

describe('Function: authorizedMembersToInput', () => {
  it('should send the groups restriction of a member', () => {
    expect(authorizedMembersToInput([member('org-x', 'view', ['group-g', 'group-h'])])).toEqual([
      { id: 'org-x', access_right: 'view', groups_restriction_ids: ['group-g', 'group-h'] },
    ]);
  });

  it('should send no groups restriction for a member without one', () => {
    expect(authorizedMembersToInput([member('org-x', 'edit')])).toEqual([
      { id: 'org-x', access_right: 'edit', groups_restriction_ids: undefined },
    ]);
  });

  it('should keep a member and the same member restricted to a group as two rules', () => {
    expect(authorizedMembersToInput([member('org-x', 'view'), member('org-x', 'view', ['group-g'])])).toEqual([
      { id: 'org-x', access_right: 'view', groups_restriction_ids: undefined },
      { id: 'org-x', access_right: 'view', groups_restriction_ids: ['group-g'] },
    ]);
  });

  it('should drop the members without access', () => {
    expect(authorizedMembersToInput([member('ALL', 'none'), member('org-x', 'admin')])).toEqual([
      { id: 'org-x', access_right: 'admin', groups_restriction_ids: undefined },
    ]);
  });

  it('should send nothing without members', () => {
    expect(authorizedMembersToInput(null)).toEqual([]);
    expect(authorizedMembersToInput(undefined)).toEqual([]);
  });
});

import { describe, expect, it } from 'vitest';
import { resolveDraftFieldDefaults, resolveAuthorizedMembersForDraft } from '../../../src/modules/form/form-domain';
import type { AuthUser } from '../../../src/types/user';

describe('resolveDraftFieldDefaults', () => {
  it('should apply schema defaults when draft fields are omitted', () => {
    const resolved = resolveDraftFieldDefaults(
      'Test Form',
      {},
      {
        description: { enabled: true, defaultValue: 'Default draft description' },
        objectAssignee: { enabled: true, defaults: [{ value: 'user-a' }] },
        objectParticipant: { enabled: true, defaults: [{ value: 'user-p' }] },
      } as any,
    );

    expect(resolved.finalDraftDescription).toBe('Default draft description');
    expect(resolved.finalDraftAssignees).toEqual(['user-a']);
    expect(resolved.finalDraftParticipants).toEqual(['user-p']);
  });

  it('should respect explicit clear values and not fallback to defaults', () => {
    const resolved = resolveDraftFieldDefaults(
      'Test Form',
      {
        draftDescription: '',
        draftObjectAssignee: [],
        draftObjectParticipant: [],
      },
      {
        description: { enabled: true, defaultValue: 'Default draft description' },
        objectAssignee: { enabled: true, defaults: [{ value: 'user-a' }] },
        objectParticipant: { enabled: true, defaults: [{ value: 'user-p' }] },
      } as any,
    );

    expect(resolved.finalDraftDescription).toBe('');
    expect(resolved.finalDraftAssignees).toEqual([]);
    expect(resolved.finalDraftParticipants).toEqual([]);
  });

  it('should fallback to configured default draft name when explicit name is empty', () => {
    const resolved = resolveDraftFieldDefaults(
      'Test Form',
      {
        draftName: '   ',
      },
      {
        name: { enabled: true, defaultValue: 'Configured draft name' },
      } as any,
    );

    expect(resolved.finalDraftName).toBe('Configured draft name');
  });

  it('should fallback to timestamp-based draft name when explicit and default names are empty', () => {
    const resolved = resolveDraftFieldDefaults(
      'Test Form',
      {
        draftName: '',
      },
      {
        name: { enabled: true, defaultValue: '' },
      } as any,
    );

    expect(resolved.finalDraftName).toMatch(/^Test Form - /);
  });

  it('should use timestamp-based draft name when no draftDefaults at all', () => {
    const resolved = resolveDraftFieldDefaults('My Form', {}, undefined);
    expect(resolved.finalDraftName).toMatch(/^My Form - /);
    expect(resolved.finalDraftDescription).toBe('');
    expect(resolved.finalDraftAssignees).toEqual([]);
    expect(resolved.finalDraftParticipants).toEqual([]);
  });

  it('should allow bypass user to override a non-editable draft name', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      { draftName: 'My Override' },
      { name: { enabled: true, isEditable: false, isRequired: false, defaultValue: 'Default Name' } } as any,
      true, // isBypass
    );
    expect(resolved.finalDraftName).toBe('My Override');
  });

  it('should block non-bypass user from overriding a non-editable draft name, using schema default instead', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      { draftName: 'Attempted Override' },
      { name: { enabled: true, isEditable: false, isRequired: false, defaultValue: 'Default Name' } } as any,
      false, // not bypass
    );
    expect(resolved.finalDraftName).toBe('Default Name');
  });

  it('should allow bypass user to override a non-editable description', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      { draftDescription: 'Override desc' },
      { description: { enabled: true, isEditable: false, isRequired: false, defaultValue: 'Default desc' } } as any,
      true,
    );
    expect(resolved.finalDraftDescription).toBe('Override desc');
  });

  it('should block non-bypass user from overriding a non-editable description', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      { draftDescription: 'Attempted Override' },
      { description: { enabled: true, isEditable: false, isRequired: false, defaultValue: 'Default desc' } } as any,
      false,
    );
    expect(resolved.finalDraftDescription).toBe('Default desc');
  });

  it('should apply description default when user has no explicit value and field is absent from submission', () => {
    // draftDescription key is absent from values (not submitted) — default should apply
    const resolved = resolveDraftFieldDefaults(
      'Form',
      {},
      { description: { enabled: true, isEditable: true, isRequired: false, defaultValue: 'Auto desc' } } as any,
    );
    expect(resolved.finalDraftDescription).toBe('Auto desc');
  });

  it('should fall back to schema defaults for assignees when user clears a non-editable field', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      { draftObjectAssignee: [] },
      {
        objectAssignee: { enabled: true, isEditable: false, isRequired: false, defaults: [{ value: 'u-1' }] },
      } as any,
      false, // non-bypass cannot edit
    );
    expect(resolved.finalDraftAssignees).toEqual(['u-1']);
  });

  it('should allow bypass user to clear assignees even when field is non-editable', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      { draftObjectAssignee: [] },
      {
        objectAssignee: { enabled: true, isEditable: false, isRequired: false, defaults: [{ value: 'u-1' }] },
      } as any,
      true, // bypass
    );
    expect(resolved.finalDraftAssignees).toEqual([]);
  });

  it('should normalize assignee defaults from object format', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      {},
      {
        objectAssignee: {
          enabled: true,
          isEditable: true,
          isRequired: false,
          defaults: [{ value: 'assignee-1', label: 'Assignee 1' }, { id: 'assignee-2', label: 'Assignee 2' }],
        },
      } as any,
    );
    expect(resolved.finalDraftAssignees).toEqual(['assignee-1', 'assignee-2']);
  });

  it('should normalize participant defaults from object format', () => {
    const resolved = resolveDraftFieldDefaults(
      'Form',
      {},
      {
        objectParticipant: {
          enabled: true,
          isEditable: true,
          isRequired: false,
          defaults: [{ value: 'p-1' }, { id: 'p-2' }],
        },
      } as any,
    );
    expect(resolved.finalDraftParticipants).toEqual(['p-1', 'p-2']);
  });
});

const makeUser = (orgs: { internal_id: string }[] = []): AuthUser => ({
  id: 'user-1',
  organizations: orgs,
} as unknown as AuthUser);

describe('resolveAuthorizedMembersForDraft', () => {
  it('should produce separate entries for same org with different group restrictions', () => {
    const user = makeUser([{ internal_id: 'org-a' }]);
    const rules = [
      { value: 'org-a', accessRight: 'edit', groupsRestriction: [{ value: 'group-analyst' }] },
      { value: 'org-a', accessRight: 'view', groupsRestriction: [{ value: 'group-manager' }] },
    ];

    const result = resolveAuthorizedMembersForDraft(user, rules);

    expect(result).toHaveLength(2);
    expect(result).toContainEqual({ id: 'org-a', access_right: 'edit', groups_restriction_ids: ['group-analyst'] });
    expect(result).toContainEqual({ id: 'org-a', access_right: 'view', groups_restriction_ids: ['group-manager'] });
  });

  it('should deduplicate identical (org, groupsRestriction) pairs — keeping first', () => {
    const user = makeUser([{ internal_id: 'org-a' }]);
    const rules = [
      { value: 'org-a', accessRight: 'edit', groupsRestriction: [{ value: 'group-analyst' }] },
      { value: 'org-a', accessRight: 'admin', groupsRestriction: [{ value: 'group-analyst' }] },
    ];

    const result = resolveAuthorizedMembersForDraft(user, rules);

    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ id: 'org-a', access_right: 'edit', groups_restriction_ids: ['group-analyst'] });
  });

  it('should produce separate entries for same org: one unrestricted, one with groups', () => {
    const user = makeUser([{ internal_id: 'org-a' }]);
    const rules = [
      { value: 'org-a', accessRight: 'admin', groupsRestriction: [] },
      { value: 'org-a', accessRight: 'view', groupsRestriction: [{ value: 'group-analyst' }] },
    ];

    const result = resolveAuthorizedMembersForDraft(user, rules);

    expect(result).toHaveLength(2);
    expect(result).toContainEqual({ id: 'org-a', access_right: 'admin', groups_restriction_ids: undefined });
    expect(result).toContainEqual({ id: 'org-a', access_right: 'view', groups_restriction_ids: ['group-analyst'] });
  });

  it('should produce separate AUTHOR entries per group restriction for the createdBy org', () => {
    const user = makeUser();
    const createdBy = 'org-a';
    const rules = [
      { type: 'AUTHOR_ORG', intersectionGroup: 'group-analyst' },
      { type: 'AUTHOR_ORG', intersectionGroup: 'group-manager' },
    ];

    const result = resolveAuthorizedMembersForDraft(user, rules, createdBy);

    // Each group restriction produces a separate entry for the createdBy org
    expect(result).toHaveLength(2);
    expect(result).toContainEqual({ id: 'org-a', access_right: 'admin', groups_restriction_ids: ['group-analyst'] });
    expect(result).toContainEqual({ id: 'org-a', access_right: 'admin', groups_restriction_ids: ['group-manager'] });
  });

  it('should always produce a single unrestricted CREATORS entry regardless of duplicates', () => {
    const user = makeUser();
    const rules = [
      { type: 'CREATOR' },
      { type: 'CREATOR' },
    ];

    const result = resolveAuthorizedMembersForDraft(user, rules);

    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ id: 'user-1', access_right: 'admin', groups_restriction_ids: undefined });
  });
});

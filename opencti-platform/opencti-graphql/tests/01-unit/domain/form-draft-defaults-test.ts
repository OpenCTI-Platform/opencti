import { describe, expect, it } from 'vitest';
import { resolveDraftFieldDefaults } from '../../../src/modules/form/form-domain';

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

  it('should not apply description default when user has no explicit value and field is not in submission', () => {
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

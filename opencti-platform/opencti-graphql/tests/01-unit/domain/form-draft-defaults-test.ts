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
});

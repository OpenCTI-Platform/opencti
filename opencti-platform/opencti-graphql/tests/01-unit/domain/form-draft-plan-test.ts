import { describe, expect, it } from 'vitest';
import { buildDraftPlan } from '../../../src/modules/form/form-domain';
import { BYPASS } from '../../../src/utils/access';

const mockUser: any = { id: 'user-1', capabilities: [{ name: BYPASS }] };
const nonBypassUser: any = { id: 'user-2', capabilities: [] };

describe('buildDraftPlan', () => {
  it('builds a draftInput with explicit author, defaults, and bypassMandatoryAttributes forced true', () => {
    const schema: any = {
      draftDefaults: {
        name: { isEditable: true },
        author: { isEditable: true, type: 'static', defaultValue: 'org-1' },
        authorizedMembers: { isEditable: true },
      },
      fields: [],
    };
    const values = { draftName: 'My Draft', draftAuthor: { value: 'org-2' } };

    const plan = buildDraftPlan('Test Form', schema, values, mockUser, true);

    expect(plan.draftInput.name).toBe('My Draft');
    expect(plan.draftInput.createdBy).toBe('org-2');
    expect(plan.draftInput.bypassMandatoryAttributes).toBe(true);
  });

  it('falls back to static author default when no explicit draftAuthor is provided', () => {
    const schema: any = {
      draftDefaults: { author: { isEditable: true, type: 'static', defaultValue: 'org-1' } },
      fields: [],
    };
    const plan = buildDraftPlan('Test Form', schema, {}, nonBypassUser, false);
    expect(plan.draftInput.createdBy).toBe('org-1');
  });

  it('honours an explicit opt-out (empty draftAuthor) when the field is editable and not required', () => {
    const schema: any = {
      draftDefaults: { author: { isEditable: true, isRequired: false, type: 'static', defaultValue: 'org-1' } },
      fields: [],
    };
    const plan = buildDraftPlan('Test Form', schema, { draftAuthor: null }, nonBypassUser, false);
    expect(plan.draftInput.createdBy).toBeUndefined();
  });
});

import { describe, expect, it } from 'vitest';
import { buildDraftPlan } from '../../../src/modules/form/form-domain';
import { BYPASS } from '../../../src/utils/access';
import { FormFieldType } from '../../../src/modules/form/form-types';

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

  it('resolves AUTHOR-type authorized-member rules from the main entity author even when "Draft Author" is left unconfigured', () => {
    const schema: any = {
      draftDefaults: {
        // No `author` config at all: the admin only configured Authorized Members.
        authorizedMembers: {
          enabled: true,
          defaults: [
            { value: 'AUTHOR', accessRight: 'view' },
            { value: 'AUTHOR', accessRight: 'edit', groupsRestriction: [{ value: 'group-analyst' }] },
          ],
        },
      },
      fields: [{ name: 'createdBy', type: FormFieldType.CreatedBy }],
    };
    const values = { createdBy: { value: 'org-a' } };

    const plan = buildDraftPlan('Test Form', schema, values, nonBypassUser, false);

    expect(plan.draftInput.createdBy).toBeUndefined();
    expect(plan.draftInput.authorized_members).toEqual([
      { id: 'org-a', access_right: 'view', groups_restriction_ids: undefined },
      { id: 'org-a', access_right: 'edit', groups_restriction_ids: ['group-analyst'] },
    ]);
  });

  it('does not grant the main entity author access to AUTHOR rules when the admin explicitly set author type to none', () => {
    const schema: any = {
      draftDefaults: {
        author: { type: 'none' },
        authorizedMembers: { enabled: true, defaults: [{ value: 'AUTHOR', accessRight: 'admin' }] },
      },
      fields: [{ name: 'createdBy', type: FormFieldType.CreatedBy }],
    };
    const values = { createdBy: { value: 'org-a' } };

    const plan = buildDraftPlan('Test Form', schema, values, nonBypassUser, false);

    expect(plan.draftInput.createdBy).toBeUndefined();
    expect(plan.draftInput.authorized_members).toBeUndefined();
  });

  it('does not grant the main entity author access to AUTHOR rules when the submitter explicitly opted out of the draft author', () => {
    const schema: any = {
      draftDefaults: {
        author: { isEditable: true, isRequired: false, type: 'static', defaultValue: 'org-1' },
        authorizedMembers: { enabled: true, defaults: [{ value: 'AUTHOR', accessRight: 'admin' }] },
      },
      fields: [{ name: 'createdBy', type: FormFieldType.CreatedBy }],
    };
    const values = { draftAuthor: null, createdBy: { value: 'org-a' } };

    const plan = buildDraftPlan('Test Form', schema, values, nonBypassUser, false);

    expect(plan.draftInput.createdBy).toBeUndefined();
    expect(plan.draftInput.authorized_members).toBeUndefined();
  });
});

import { vi, describe, it, expect, beforeEach } from 'vitest';
import { formSubmit } from '../../../src/modules/form/form-domain';
import * as draftWorkspaceDomain from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as workDomain from '../../../src/domain/work';
import { BYPASS } from '../../../src/utils/access';

const { mockStoreLoadById } = vi.hoisted(() => ({
  mockStoreLoadById: vi.fn(),
}));

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain');
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: mockStoreLoadById,
  internalLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
}));
vi.mock('../../../src/domain/work');
vi.mock('../../../src/manager/telemetryManager', () => ({
  addFormIntakeSubmittedCount: vi.fn().mockResolvedValue(undefined),
}));

const mockUser: any = {
  id: 'user-1',
  individual_id: 'individual-1',
  name: 'User 1',
  origin: { user_id: 'user-1' },
  roles: [],
  groups: [],
  capabilities: [],
  organizations: [],
  allowed_marking: [],
};

const mockContext: any = {
  user: mockUser,
  tracing: {
    getTracer: () => ({ startSpan: () => ({ end: () => {} }) }),
  },
};

const mockForm: any = {
  id: 'form-1',
  name: 'Test Form',
  form_schema: JSON.stringify({
    fields: [
      { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
    ],
    mainEntityType: 'Individual',
    draftDefaults: {
      author: { type: 'current_user', isEditable: false },
      authorizedMembers: { enabled: true, defaults: [] },
    },
  }),
};

describe('formSubmit', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // Default mocks
    mockStoreLoadById.mockResolvedValue(mockForm);
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'work-1' } as any);
    vi.spyOn(draftWorkspaceDomain, 'addDraftWorkspace').mockResolvedValue({ id: 'draft-1' } as any);
  });

  it('should use current user as createdBy when configured in schema', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    // Override mock form schema for this test
    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        author: { type: 'current_user', isEditable: false },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true); // isDraft=true

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        createdBy: 'individual-1',
      }),
    );
  });

  it('should use main entity author as createdBy when configured in schema', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({
        name: 'Test Individual',
        createdBy: 'author-1',
      }),
    };

    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        author: { type: 'main_entity_author', isEditable: false },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        createdBy: 'author-1',
      }),
    );
  });

  it('should resolve authorized members with intersection logic', async () => {
    const orgId = 'org-1';
    const userWithOrg = {
      ...mockUser,
      organizations: [{ internal_id: orgId }],
    };

    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        authorizedMembers: {
          enabled: true,
          defaults: [
            { type: 'AUTHOR_ORG', intersectionGroup: 'group-1' }, // Old format equivalent to AUTHOR with group restriction
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, userWithOrg, input, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({
            id: orgId,
            groups_restriction_ids: ['group-1'],
          }),
        ]),
      }),
    );
  });

  it('should resolve dynamic authorized members logic (AUTHOR)', async () => {
    const orgId = 'org-1';
    const userWithOrg = {
      ...mockUser,
      organizations: [{ internal_id: orgId }],
    };

    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        authorizedMembers: {
          enabled: true,
          defaults: [
            { value: 'AUTHOR', accessRight: 'view', groupsRestriction: [{ value: 'group-2' }] },
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, userWithOrg, input, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({
            id: orgId,
            access_right: 'view',
            groups_restriction_ids: ['group-2'],
          }),
        ]),
      }),
    );
  });

  it('should resolve groupsRestriction from id entries in schema defaults', async () => {
    const orgId = 'org-1';
    const userWithOrg = {
      ...mockUser,
      organizations: [{ internal_id: orgId }],
    };

    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        authorizedMembers: {
          enabled: true,
          defaults: [
            { value: 'AUTHOR', accessRight: 'view', groupsRestriction: [{ id: 'group-id-only' }] },
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, userWithOrg, input, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({
            id: orgId,
            access_right: 'view',
            groups_restriction_ids: ['group-id-only'],
          }),
        ]),
      }),
    );
  });

  it('should resolve groupsRestriction from id entries in explicit BYPASS members', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({
        name: 'Test Individual',
        draftAuthorizedMembers: [
          {
            value: 'user-2',
            accessRight: 'admin',
            groupsRestriction: [{ id: 'group-id-only' }],
          },
        ],
      }),
    };

    const userByPass = { ...mockUser, capabilities: [{ name: BYPASS }] };
    mockStoreLoadById.mockResolvedValue(mockForm);

    await formSubmit(mockContext, userByPass, input, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({
            id: 'user-2',
            access_right: 'admin',
            groups_restriction_ids: ['group-id-only'],
          }),
        ]),
      }),
    );
  });

  it('should ignore user-submitted authorized members if user has no BYPASS capability', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({
        name: 'Test Individual',
        draftAuthorizedMembers: [{ id: 'user-2', accessRight: 'admin' }],
      }),
    };

    const userNoBypass = { ...mockUser, capabilities: [] };
    mockStoreLoadById.mockResolvedValue(mockForm);

    await formSubmit(mockContext, userNoBypass, input, true);

    // Should NOT contain the user-submitted member
    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.not.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({ id: 'user-2' }),
        ]),
      }),
    );
  });

  it('should accept user-submitted authorized members if user HAS BYPASS capability', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({
        name: 'Test Individual',
        draftAuthorizedMembers: [{ value: 'user-2', accessRight: 'admin' }],
      }),
    };

    const userByPass = { ...mockUser, capabilities: [{ name: BYPASS }] };
    mockStoreLoadById.mockResolvedValue(mockForm);

    await formSubmit(mockContext, userByPass, input, true);

    // Should contain the user-submitted member
    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({ id: 'user-2', access_right: 'admin' }),
        ]),
      }),
    );
  });

  it('should apply configured draft defaults when draft fields are omitted', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        description: { enabled: true, defaultValue: 'Default draft description', isEditable: true, isRequired: false },
        objectAssignee: { enabled: true, defaults: [{ value: 'user-a' }], isEditable: true, isRequired: false },
        objectParticipant: { enabled: true, defaults: [{ value: 'user-p' }], isEditable: true, isRequired: false },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

    const draftInput = vi.mocked(draftWorkspaceDomain.addDraftWorkspace).mock.calls[0][2] as any;
    expect(draftInput.description).toBe('Default draft description');
    expect(draftInput.objectAssignee).toEqual(['user-a']);
    expect(draftInput.objectParticipant).toEqual(['user-p']);
  });

  it('should respect explicit clear values and not fallback to defaults', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({
        name: 'Test Individual',
        draftDescription: '',
        draftObjectAssignee: [],
        draftObjectParticipant: [],
      }),
    };

    const form = { ...mockForm };
    form.form_schema = JSON.stringify({
      fields: [
        { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
      ],
      mainEntityType: 'Individual',
      draftDefaults: {
        description: { enabled: true, defaultValue: 'Default draft description', isEditable: true, isRequired: false },
        objectAssignee: { enabled: true, defaults: [{ value: 'user-a' }], isEditable: true, isRequired: false },
        objectParticipant: { enabled: true, defaults: [{ value: 'user-p' }], isEditable: true, isRequired: false },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

    const draftInput = vi.mocked(draftWorkspaceDomain.addDraftWorkspace).mock.calls[0][2] as any;
    expect(draftInput.description).toBeUndefined();
    expect(draftInput.objectAssignee).toBeUndefined();
    expect(draftInput.objectParticipant).toBeUndefined();
  });
});

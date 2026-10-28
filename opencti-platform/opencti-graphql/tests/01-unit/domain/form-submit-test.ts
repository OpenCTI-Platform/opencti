import { vi, describe, it, expect, beforeEach } from 'vitest';
import { formSubmit } from '../../../src/modules/form/form-domain';
import * as draftWorkspaceDomain from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as workDomain from '../../../src/domain/work';
import * as rabbitmq from '../../../src/database/rabbitmq';
import * as redis from '../../../src/database/redis';
import { BYPASS, SYSTEM_USER } from '../../../src/utils/access';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { connectorIdFromIngestId } from '../../../src/domain/connector';
import { Readable } from 'stream';
import { logApp } from '../../../src/config/conf';

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
vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../src/domain/work');
vi.mock('../../../src/database/rabbitmq', () => ({
  pushBundleToWorker: vi.fn(),
  pushToConnector: vi.fn(),
}));
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisDeleteWorks: vi.fn(),
}));
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
  capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }],
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
      author: { type: 'none', isEditable: false },
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

  it('should use static identity as createdBy when configured in schema', async () => {
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
        author: { type: 'static', isEditable: false, defaultValue: 'identity-42' },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true); // isDraft=true

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        createdBy: 'identity-42',
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
        author: { type: 'static', defaultValue: orgId, isEditable: false },
        authorizedMembers: {
          enabled: true,
          defaults: [
            { type: 'AUTHOR_ORG', intersectionGroup: 'group-1' }, // Old format equivalent to AUTHOR with group restriction
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

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
        author: { type: 'static', defaultValue: orgId, isEditable: false },
        authorizedMembers: {
          enabled: true,
          defaults: [
            { value: 'AUTHOR', accessRight: 'view', groupsRestriction: [{ value: 'group-2' }] },
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

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

  it('should ignore groups restriction for dynamic authorized members logic (CREATORS)', async () => {
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
            { value: 'CREATORS', accessRight: 'edit', groupsRestriction: [{ value: 'group-creators' }] },
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledWith(
      expect.anything(),
      SYSTEM_USER,
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({
            id: mockUser.id,
            // Access right is determined solely by the form schema (CREATORS rule with 'edit').
            access_right: 'edit',
            groups_restriction_ids: undefined,
          }),
        ]),
      }),
    );
  });

  it('should resolve groupsRestriction from id entries in schema defaults', async () => {
    const orgId = 'org-1';

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
        author: { type: 'static', defaultValue: orgId, isEditable: false },
        authorizedMembers: {
          enabled: true,
          defaults: [
            { value: 'AUTHOR', accessRight: 'view', groupsRestriction: [{ id: 'group-id-only' }] },
          ],
        },
      },
    });
    mockStoreLoadById.mockResolvedValue(form);

    await formSubmit(mockContext, mockUser, input, true);

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

    const userNoBypass = { ...mockUser, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] };
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

  it('should send bundle with no_split:true to prevent race condition with multiple workers', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    mockStoreLoadById.mockResolvedValue(mockForm);
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'work-1' } as any);
    vi.spyOn(workDomain, 'updateExpectationsNumber').mockResolvedValue(undefined as any);

    await formSubmit(mockContext, mockUser, input, false); // isDraft=false → pushBundleToWorker path

    const pushSpy = vi.mocked(rabbitmq.pushBundleToWorker);
    expect(pushSpy).toHaveBeenCalledOnce();
    const message = pushSpy.mock.calls[0][3];
    expect(message).toMatchObject({ no_split: true });
  });

  it('should bypass mandatory attributes when creating draft from form intake', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    mockStoreLoadById.mockResolvedValue(mockForm);

    await formSubmit(mockContext, mockUser, input, true);

    const draftInput = vi.mocked(draftWorkspaceDomain.addDraftWorkspace).mock.calls[0][2] as any;
    expect(draftInput.bypassMandatoryAttributes).toBe(true);
  });
});

describe('formSubmit - deferred creation', () => {
  const lookupForm: any = {
    id: 'form-1',
    name: 'Lookup Form',
    form_schema: JSON.stringify({ fields: [], mainEntityType: 'Malware', mainEntityLookup: true }),
  };
  // Creating a label is a right of its own, the pending labels of these tests need it
  const labelManager = { ...mockUser, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }, { name: 'SETTINGS_SETLABELS' }] };
  const pushedBundle = () => {
    const message = vi.mocked(rabbitmq.pushBundleToWorker).mock.calls[0][3] as any;
    return JSON.parse(Buffer.from(message.content, 'base64').toString('utf-8'));
  };
  const upload = (content: string) => Promise.resolve({
    filename: 'report.txt',
    mimetype: 'text/plain',
    createReadStream: () => Readable.from([Buffer.from(content)]),
  });

  beforeEach(() => {
    vi.resetAllMocks();
    mockStoreLoadById.mockResolvedValue(lookupForm);
    // The schema is not registered in this test: the attributes of the pending objects are checked in form-pending-test
    vi.spyOn(schemaAttributesDefinition, 'getAttribute').mockReturnValue({ type: 'string' } as any);
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue(null);
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'work-1' } as any);
    vi.mocked(internalLoadById).mockImplementation((async (_c: any, _u: any, id: string) => ({
      'marking-1': { internal_id: 'marking-1', standard_id: 'marking-definition--1', entity_type: 'Marking-Definition' },
    } as any)[id]) as any);
  });

  it('should accept a pending-only lookup and bundle its refs and files', async () => {
    const values = {
      mainEntityLookupPending: [{
        entityType: 'Malware',
        input: { name: 'Pending Malware', is_family: true },
        refs: { objectMarking: [{ existing: 'marking-1' }], objectLabel: [{ pending: 'l1' }], externalReferences: [{ pending: 'e1' }] },
        files: [{ name: 'evidence.txt', uploadIndex: 0 }],
      }],
      pendingObjects: [
        { id: 'l1', entityType: 'Label', input: { value: 'new-label' } },
        { id: 'e1', entityType: 'External-Reference', input: { source_name: 'src', url: 'https://example.com' } },
        { id: 'unused', entityType: 'Label', input: { value: 'not-submitted' } },
      ],
    };

    const result = await formSubmit(mockContext, labelManager, { formId: 'form-1', values: JSON.stringify(values), files: [upload('hello')] } as any, false);

    expect(result.success).toBe(true);
    const malware = pushedBundle().objects.find((o: any) => o.name === 'Pending Malware');
    expect(malware.labels).toEqual(['new-label']);
    expect(malware.object_marking_refs).toEqual(['marking-definition--1']);
    expect(malware.external_references).toEqual([{ source_name: 'src', url: 'https://example.com' }]);
    expect(JSON.stringify(malware)).toContain(Buffer.from('hello').toString('base64'));
    expect(JSON.stringify(pushedBundle())).not.toContain('not-submitted');
  });

  it('should resolve pending labels and external references sent from direct fields', async () => {
    const field = (name: string, type: string) => ({ name, label: name, type, attributeMapping: { entity: 'main_entity', attributeName: name } });
    mockStoreLoadById.mockResolvedValue({
      id: 'form-1',
      name: 'Direct Form',
      form_schema: JSON.stringify({
        mainEntityType: 'Malware',
        fields: [field('name', 'text'), field('objectLabel', 'objectLabel'), field('externalReferences', 'externalReferences')],
      }),
    });
    const values = {
      name: 'Direct Malware',
      objectLabel: ['existing-label', { pending: 'l1' }],
      externalReferences: [{ pending: 'e1' }],
      pendingObjects: [
        { id: 'l1', entityType: 'Label', input: { value: 'new-label' } },
        { id: 'e1', entityType: 'External-Reference', input: { source_name: 'src', url: 'https://example.com' } },
      ],
    };

    await formSubmit(mockContext, labelManager, { formId: 'form-1', values: JSON.stringify(values) }, false);

    const malware = pushedBundle().objects.find((o: any) => o.name === 'Direct Malware');
    expect(malware.labels).toEqual(['existing-label', 'new-label']);
    expect(malware.external_references).toEqual([{ source_name: 'src', url: 'https://example.com' }]);
  });

  it('should send the files of a pending external reference with it in the bundle', async () => {
    const values = {
      mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'File Malware' }, refs: { externalReferences: [{ pending: 'e1' }] } }],
      pendingObjects: [{ id: 'e1', entityType: 'External-Reference', input: { source_name: 'src', external_id: 'REF-1' }, files: [{ name: 'report.txt', uploadIndex: 0 }] }],
    };

    await formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values), files: [upload('report')] } as any, false);

    const malware = pushedBundle().objects.find((o: any) => o.name === 'File Malware');
    expect(malware.external_references).toEqual([
      { source_name: 'src', external_id: 'REF-1', x_opencti_files: [{ name: 'report.txt', data: Buffer.from('report').toString('base64'), mime_type: 'text/plain' }] },
    ]);
  });

  it('should refuse the labels created in the form to a user who cannot manage labels', async () => {
    const values = {
      mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'Labelled Malware' }, refs: { objectLabel: [{ pending: 'l1' }] } }],
      pendingObjects: [{ id: 'l1', entityType: 'Label', input: { value: 'new-label' } }],
    };
    const submit = (user: any, isDraft: boolean) => formSubmit(mockContext, user, { formId: 'form-1', values: JSON.stringify(values) }, isDraft);
    const editor = { ...mockUser, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] };
    await expect(submit(editor, false)).rejects.toThrow('You are not allowed to create labels.');
    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
    // the right of the draft scope counts for a draft destination only
    const inDraft = { ...editor, capabilitiesInDraft: [{ name: 'SETTINGS_SETLABELS' }] };
    vi.spyOn(draftWorkspaceDomain, 'addDraftWorkspace').mockResolvedValue({ id: 'draft-1' } as any);
    await expect(submit(inDraft, false)).rejects.toThrow('You are not allowed to create labels.');
    await expect(submit(inDraft, true)).resolves.toMatchObject({ success: true });
    await expect(submit({ ...mockUser, capabilities: [{ name: BYPASS }] }, false)).resolves.toMatchObject({ success: true });
  });

  it('should still accept the legacy pending payload', async () => {
    const values = { mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'Legacy Malware' } }] };

    await formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values) }, false);

    expect(pushedBundle().objects.map((o: any) => o.name)).toContain('Legacy Malware');
  });

  it('should bundle the files and the markdown images of an object created in an additional lookup', async () => {
    const token = '00000000-0000-0000-0000-00000000000a';
    mockStoreLoadById.mockResolvedValue({
      id: 'form-1',
      name: 'Additional Form',
      form_schema: JSON.stringify({
        mainEntityType: 'Individual',
        fields: [{ name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } }],
        additionalEntities: [{ id: 'threat', label: 'Threat', entityType: 'Malware', multiple: true, lookup: true, parseFieldMapping: 'name' }],
      }),
    });
    const values = {
      name: 'Main Individual',
      additional_threat_lookup_pending: [{
        entityType: 'Malware',
        input: { name: 'Extra Malware', description: `see ![shot](opencti-image://temp/${token})` },
        files: [{ name: 'shot.png', uploadIndex: 0, embedded: true }, { name: 'evidence.txt', uploadIndex: 1 }],
      }],
    };
    const png = Promise.resolve({ filename: 'shot.png', mimetype: 'image/png', createReadStream: () => Readable.from([Buffer.from('png')]) });

    await formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values), files: [png, upload('evidence')] } as any, false);

    const malware = pushedBundle().objects.find((o: any) => o.name === 'Extra Malware');
    expect(malware.description).toBe(`see ![shot](data:image/png;base64,${Buffer.from('png').toString('base64')})`);
    expect(JSON.stringify(malware)).toContain(Buffer.from('evidence').toString('base64'));
    expect(pushedBundle().objects.map((o: any) => o.name)).toContain('Main Individual');
  });

  it('should plan a draft submission with the object created in the form', async () => {
    vi.mocked(draftWorkspaceDomain.addDraftWorkspace).mockResolvedValue({ id: 'draft-1' } as any);
    mockStoreLoadById.mockResolvedValue({
      ...lookupForm,
      form_schema: JSON.stringify({
        fields: [],
        mainEntityType: 'Malware',
        mainEntityLookup: true,
        draftDefaults: { author: { type: 'none', isEditable: false }, authorizedMembers: { enabled: true, defaults: [] } },
      }),
    });
    const values = { mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'Draft Malware' }, refs: { objectLabel: [{ pending: 'l1' }] } }], pendingObjects: [{ id: 'l1', entityType: 'Label', input: { value: 'draft-label' } }] };

    const result = await formSubmit(mockContext, labelManager, { formId: 'form-1', values: JSON.stringify(values) }, true);

    expect(draftWorkspaceDomain.addDraftWorkspace).toHaveBeenCalledTimes(1);
    expect(vi.mocked(rabbitmq.pushBundleToWorker).mock.calls[0][3]).toMatchObject({ draft_id: 'draft-1', applicant_id: 'user-1' });
    expect(result.entityId).toBe('draft-1');
    expect(pushedBundle().objects.find((o: any) => o.name === 'Draft Malware').labels).toEqual(['draft-label']);
  });

  it('should reject an external reference object sent in a direct field that is not in the pool', async () => {
    mockStoreLoadById.mockResolvedValue({
      id: 'form-1',
      name: 'Direct Form',
      form_schema: JSON.stringify({
        mainEntityType: 'Malware',
        fields: [
          { name: 'name', label: 'name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
          { name: 'externalReferences', label: 'refs', type: 'externalReferences', attributeMapping: { entity: 'main_entity', attributeName: 'externalReferences' } },
        ],
      }),
    });
    const forged = { source_name: 'forged', x_opencti_files: [{ name: 'a.txt', data: 'ZGF0YQ==' }] };
    const values = { name: 'Forged Malware', externalReferences: [forged] };

    await expect(formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values) }, false))
      .rejects.toThrow('An external reference must be an existing one or one created in the form');

    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
  });

  it('should reject a root the form schema does not allow without creating a work or pushing a bundle', async () => {
    const values = { mainEntityLookupPending: [{ entityType: 'Report', input: { name: 'Not a malware' } }] };

    await expect(formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values) }, false))
      .rejects.toThrow('cannot create an object of this type');

    expect(workDomain.createWork).not.toHaveBeenCalled();
    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
  });

  it('should reject an upload no object references before reading it', async () => {
    const values = { mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'M' } }] };
    const unreferenced = { filename: 'a.txt', mimetype: 'text/plain', createReadStream: vi.fn(() => Readable.from([Buffer.from('a')])) };

    await expect(formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values), files: [Promise.resolve(unreferenced)] } as any, false))
      .rejects.toThrow('An upload is not referenced by any object created in the form');

    expect(unreferenced.createReadStream).not.toHaveBeenCalled();
    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
  });

  it('should log the id and the object count of the bundle, not its content', async () => {
    const info = vi.spyOn(logApp, 'info').mockImplementation(() => logApp);
    const values = { mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'Logged Malware' } }] };

    await formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values) }, false);

    const generated = info.mock.calls.find(([message]) => message === '[FORM] STIX Bundle generated');
    expect(generated?.[1]).toEqual({ bundleId: expect.stringMatching(/^bundle--/), objectCount: 1 });
    expect(JSON.stringify(info.mock.calls)).not.toContain('Logged Malware');
  });

  it('should reject an invalid pending payload without creating a work or pushing a bundle', async () => {
    const values = { mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'M' }, refs: { objectLabel: [{ pending: 'missing' }] } }] };

    await expect(formSubmit(mockContext, mockUser, { formId: 'form-1', values: JSON.stringify(values) }, false))
      .rejects.toThrow('Pending ref not found in submission');

    expect(workDomain.createWork).not.toHaveBeenCalled();
    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
  });
});

describe('formSubmit - access to the destination', () => {
  const values = JSON.stringify({ name: 'Test Individual' });
  const submit = (user: any, isDraft: boolean) => formSubmit(mockContext, user, { formId: 'form-1', values }, isDraft);
  const caps = (...names: string[]) => names.map((name) => ({ name }));

  beforeEach(() => {
    vi.resetAllMocks();
    mockStoreLoadById.mockResolvedValue(mockForm);
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'work-1' } as any);
    vi.spyOn(draftWorkspaceDomain, 'addDraftWorkspace').mockResolvedValue({ id: 'draft-1' } as any);
  });

  it('should let a user with only the form capability submit to the main destination', async () => {
    const result = await submit({ ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE') }, false);
    expect(result.success).toBe(true);
  });

  it('should reject a user without Create / Update knowledge nor the form capability', async () => {
    await expect(submit({ ...mockUser, capabilities: caps('KNOWLEDGE_KNASKIMPORT') }, false)).rejects.toThrow('You are not allowed to submit forms in this destination.');
    expect(workDomain.createWork).not.toHaveBeenCalled();
  });

  it('should let a user with only the form capability attach an existing kill chain phase to an object created in the form', async () => {
    // attaching an existing phase needs no right to manage kill chain phases (see addKillChainPhase)
    mockStoreLoadById.mockResolvedValue({
      ...mockForm,
      form_schema: JSON.stringify({ fields: [], mainEntityType: 'Malware', mainEntityLookup: true }),
    });
    vi.spyOn(schemaAttributesDefinition, 'getAttribute').mockReturnValue({ type: 'string' } as any);
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue(null);
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: 'phase-1', standard_id: 'kill-chain-phase--1', entity_type: 'Kill-Chain-Phase', kill_chain_name: 'mitre', phase_name: 'execution' } as any);
    const withPhase = JSON.stringify({ mainEntityLookupPending: [{ entityType: 'Malware', input: { name: 'M' }, refs: { killChainPhases: [{ existing: 'phase-1' }] } }] });
    const result = await formSubmit(mockContext, { ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE') }, { formId: 'form-1', values: withPhase }, false);
    expect(result.success).toBe(true);
  });

  it('should reject a malformed payload with its validation error before checking the access', async () => {
    const malformed = JSON.stringify({ name: 'Test Individual', mainEntityLookupPending: [null] });
    const formOnly = { ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE') };
    await expect(formSubmit(mockContext, formOnly, { formId: 'form-1', values: malformed }, false)).rejects.toThrow('An object created in a form must be an object');
  });

  it('should reject a main submission when the capability is only granted in draft', async () => {
    const draftOnly = { ...mockUser, capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNFORMINTAKE') };
    await expect(submit(draftOnly, false)).rejects.toThrow('You are not allowed to submit forms in this destination.');
    const result = await submit(draftOnly, true);
    expect(result.success).toBe(true);
  });

  it('should require the label right to create labels, whatever the form capability', async () => {
    const withLabel = JSON.stringify({
      name: 'With label',
      pendingObjects: [{ id: 'l1', entityType: 'Label', input: { value: 'new-label' } }],
    });
    const formOnly = { ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE') };
    await expect(formSubmit(mockContext, formOnly, { formId: 'form-1', values: withLabel }, false)).rejects.toThrow('You are not allowed to create labels.');
    const withRight = { ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE', 'SETTINGS_SETLABELS') };
    await expect(formSubmit(mockContext, withRight, { formId: 'form-1', values: withLabel }, false)).resolves.toMatchObject({ success: true });
  });

  it('should bind the work to the applicant, the form and the draft of the submission', async () => {
    await submit({ ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE') }, true);
    const connectorId = connectorIdFromIngestId('form-1');
    expect(workDomain.createWork).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      { internal_id: connectorId, connector_type: 'EXTERNAL_IMPORT' },
      expect.stringMatching(/^Form submission @ /),
      connectorId,
      { receivedTime: expect.any(String), formSubmission: { applicant_id: 'user-1', form_id: 'form-1', draft_id: 'draft-1' } },
    );
  });

  it('should bind a main submission to no draft', async () => {
    await submit({ ...mockUser, capabilities: caps('KNOWLEDGE_KNFORMINTAKE') }, false);
    expect(vi.mocked(workDomain.createWork).mock.calls[0][5]).toMatchObject({ formSubmission: { applicant_id: 'user-1', form_id: 'form-1', draft_id: null } });
  });

  it('should import a main submission made inside a draft into that draft, with the access of the draft scope', async () => {
    const draftOnly = { ...mockUser, capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNFORMINTAKE') };
    const inDraft: any = { ...mockContext, draft_context: 'draft-current' };
    await expect(formSubmit(inDraft, draftOnly, { formId: 'form-1', values }, false)).resolves.toMatchObject({ success: true });
    expect(draftWorkspaceDomain.addDraftWorkspace).not.toHaveBeenCalled();
    expect(vi.mocked(workDomain.createWork).mock.calls[0][5]).toMatchObject({ formSubmission: { applicant_id: 'user-1', form_id: 'form-1', draft_id: 'draft-current' } });
    expect(vi.mocked(rabbitmq.pushBundleToWorker).mock.calls[0][3]).toMatchObject({ draft_id: 'draft-current' });
  });

  it('should keep letting a user with only Import knowledge in the draft scope submit into a draft', async () => {
    const importInDraft = { ...mockUser, capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNASKIMPORT') };
    await expect(submit(importInDraft, true)).resolves.toMatchObject({ success: true });
    await expect(submit(importInDraft, false)).rejects.toThrow('You are not allowed to submit forms in this destination.');
  });

  it('should let a BYPASS user submit without the form capability', async () => {
    const result = await submit({ ...mockUser, capabilities: caps(BYPASS) }, false);
    expect(result.success).toBe(true);
  });
});

describe('formSubmit - failure after the draft is created', () => {
  const values = JSON.stringify({ name: 'Test Individual' });
  const submit = (isDraft: boolean) => formSubmit(mockContext, mockUser, { formId: 'form-1', values }, isDraft);

  beforeEach(() => {
    vi.resetAllMocks();
    mockStoreLoadById.mockResolvedValue(mockForm);
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'work-1' } as any);
    vi.spyOn(draftWorkspaceDomain, 'addDraftWorkspace').mockResolvedValue({ id: 'draft-1' } as any);
  });

  it('should delete the draft of the submission when the work cannot be created', async () => {
    vi.mocked(workDomain.createWork).mockRejectedValue(new Error('work failure'));
    await expect(submit(true)).rejects.toThrow('Failed to process form submission');
    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
    expect(workDomain.updateProcessedTime).not.toHaveBeenCalled();
    expect(draftWorkspaceDomain.deleteDraftWorkspace).toHaveBeenCalledOnce();
    expect(draftWorkspaceDomain.deleteDraftWorkspace).toHaveBeenCalledWith(expect.objectContaining({ draft_context: undefined }), SYSTEM_USER, 'draft-1');
  });

  it('should close the work in error and delete the draft when the bundle cannot be pushed', async () => {
    vi.mocked(rabbitmq.pushBundleToWorker).mockRejectedValue(new Error('queue failure'));
    await expect(submit(true)).rejects.toThrow('Failed to process form submission');
    expect(workDomain.updateProcessedTime).toHaveBeenCalledWith(mockContext, SYSTEM_USER, 'work-1', expect.any(String), true);
    expect(draftWorkspaceDomain.deleteDraftWorkspace).toHaveBeenCalledWith(expect.anything(), SYSTEM_USER, 'draft-1');
  });

  it('should end the live state of the work first, so a bundle that still reached the queue is skipped', async () => {
    vi.mocked(rabbitmq.pushBundleToWorker).mockRejectedValue(new Error('queue failure after the broker accepted it'));
    await expect(submit(false)).rejects.toThrow('Failed to process form submission');
    expect(redis.redisDeleteWorks).toHaveBeenCalledWith(['work-1']);
    expect(vi.mocked(redis.redisDeleteWorks).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(workDomain.updateProcessedTime).mock.invocationCallOrder[0]);
  });

  it('should rethrow the original error as the cause', async () => {
    const failure = new Error('queue failure');
    vi.mocked(rabbitmq.pushBundleToWorker).mockRejectedValue(failure);
    const error: any = await submit(true).catch((e) => e);
    expect(error.cause ?? error.data?.cause ?? error.extensions?.data?.cause).toBe(failure);
  });

  it('should delete the draft when it cannot be completed, before any work exists', async () => {
    const { patchAttribute } = await import('../../../src/database/middleware');
    vi.mocked(patchAttribute).mockRejectedValue(new Error('patch failure'));
    await expect(submit(true)).rejects.toThrow('Failed to process form submission');
    expect(workDomain.createWork).not.toHaveBeenCalled();
    expect(draftWorkspaceDomain.deleteDraftWorkspace).toHaveBeenCalledWith(expect.anything(), SYSTEM_USER, 'draft-1');
  });

  it('should only close the work when the submission has no draft', async () => {
    vi.mocked(rabbitmq.pushBundleToWorker).mockRejectedValue(new Error('queue failure'));
    await expect(submit(false)).rejects.toThrow('Failed to process form submission');
    expect(workDomain.updateProcessedTime).toHaveBeenCalledOnce();
    expect(draftWorkspaceDomain.deleteDraftWorkspace).not.toHaveBeenCalled();
  });

  it('should still report the submission error when the cleanup fails too', async () => {
    vi.mocked(rabbitmq.pushBundleToWorker).mockRejectedValue(new Error('queue failure'));
    vi.mocked(redis.redisDeleteWorks).mockRejectedValue(new Error('redis cleanup failure'));
    vi.mocked(workDomain.updateProcessedTime).mockRejectedValue(new Error('work cleanup failure'));
    vi.mocked(draftWorkspaceDomain.deleteDraftWorkspace).mockRejectedValue(new Error('draft cleanup failure'));
    await expect(submit(true)).rejects.toThrow('Failed to process form submission');
    expect(draftWorkspaceDomain.deleteDraftWorkspace).toHaveBeenCalledOnce();
  });

  it('should keep the draft and the work of a submission that was sent', async () => {
    await expect(submit(true)).resolves.toMatchObject({ success: true, entityId: 'draft-1' });
    expect(draftWorkspaceDomain.deleteDraftWorkspace).not.toHaveBeenCalled();
    expect(workDomain.updateProcessedTime).not.toHaveBeenCalled();
    expect(redis.redisDeleteWorks).not.toHaveBeenCalled();
  });
});

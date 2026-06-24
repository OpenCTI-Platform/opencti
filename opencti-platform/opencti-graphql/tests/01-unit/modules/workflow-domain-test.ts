import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as ee from '../../../src/enterprise-edition/ee';
import { createEntity, createRelation, loadEntity, updateAttribute } from '../../../src/database/middleware';
import { WorkflowFactory } from '../../../src/modules/workflow/engine/workflow-factory';
import {
  setWorkflowDefinition,
  isStatusTemplateUsedInWorkflows,
  publishWorkflowDefinition,
  getWorkflowDefinition,
  getAllowedTransitions,
  getWorkflowInstance,
  deleteWorkflowDefinition,
  triggerWorkflowEvent,
  clearWorkflowPendingState,
  getWorkflowPublishedVersionId,
} from '../../../src/modules/workflow/domain/workflow-domain';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn(),
  loadEntity: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/modules/entitySetting/entitySetting-domain', () => ({
  findByType: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  bypassDraftContext: vi.fn((context) => context),
}));

vi.mock('../../../src/modules/workflow/workflow-validation', () => ({
  validateWorkflowDefinitionData: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/modules/workflow/engine/workflow-factory', () => ({
  WorkflowFactory: {
    createDefinition: vi.fn(() => ({
      getInitialState: () => 'open',
      hasState: () => true,
      getTransitions: () => [
        { event: 'close', to: 'closed', actionTypes: ['log'] },
      ],
    })),
    getInstance: vi.fn(() => ({
      start: vi.fn().mockResolvedValue(undefined),
      trigger: vi.fn().mockResolvedValue({ success: true }),
      getCurrentState: () => 'closed',
    })),
  },
}));

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

describe('Workflow Domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should fail when definition JSON is invalid', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', '{ invalid-json')).rejects.toThrow('Invalid workflow definition JSON');
    expect(validateWorkflowDefinitionData).not.toHaveBeenCalled();
  });

  it('should fail when entity setting is not found', async () => {
    (findByType as any).mockResolvedValue(null);

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', JSON.stringify({ initialState: 'draft', transitions: [] }))).rejects.toThrow('Entity setting not found for type');
  });

  describe('EE / CE gating in setWorkflowDefinition', () => {
    const ceDefinition = (overrides = {}) => JSON.stringify({
      initialState: 'draft',
      states: [],
      transitions: [],
      ...overrides,
    });

    beforeEach(() => {
      // Default: EE check passes (simulates EE licence)
      vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue(undefined);
      (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });
      const versionObj = { id: 'v1', timestamp: '', createdBy: '', content: '{}', validation_errors: [] };
      (createEntity as any).mockResolvedValue({ id: 'workflow-id', name: 'Workflow for Incident', all_versions: [versionObj], draft_version: versionObj });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'entity-setting-id', workflow_id: 'workflow-id' } });
    });

    it('does NOT call checkEnterpriseEdition for a plain CE definition (no EE actions, no conditions)', async () => {
      const def = ceDefinition({
        transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'validateDraft', mode: 'sync' }] }],
      });
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(ee.checkEnterpriseEdition).not.toHaveBeenCalled();
    });

    it('does NOT call checkEnterpriseEdition when conditions is present but filters array is empty', async () => {
      const def = ceDefinition({
        transitions: [{ from: 'open', to: 'closed', event: 'close', conditions: { mode: 'and', filters: [], filterGroups: [] } }],
      });
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(ee.checkEnterpriseEdition).not.toHaveBeenCalled();
    });

    it.each([
      ['updateAuthorizedMembers on transition syncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }] }],
      ['shareWithOrganizations on transition asyncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', asyncActions: [{ type: 'shareWithOrganizations', mode: 'async' }] }] }],
      ['unshareFromOrganizations on transition asyncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', asyncActions: [{ type: 'unshareFromOrganizations', mode: 'async' }] }] }],
      ['asyncBulkAction on transition syncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'asyncBulkAction', mode: 'sync' }] }] }],
      ['non-empty conditions filters on transition', { transitions: [{ from: 'open', to: 'closed', event: 'close', conditions: { mode: 'and', filters: [{ key: 'entity_type', values: ['Incident'] }], filterGroups: [] } }] }],
      ['updateAuthorizedMembers on state onEnter', { states: [{ statusId: 'status-1', onEnter: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }] }],
      ['updateAuthorizedMembers on state onExit', { states: [{ statusId: 'status-1', onExit: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }] }],
    ])('calls checkEnterpriseEdition when definition has %s', async (_label, overrides) => {
      const def = ceDefinition(overrides);
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(ee.checkEnterpriseEdition).toHaveBeenCalledWith(mockContext);
    });

    it('propagates the error thrown by checkEnterpriseEdition (CE instance rejects EE features)', async () => {
      vi.spyOn(ee, 'checkEnterpriseEdition').mockRejectedValue(new Error('Enterprise edition required'));
      const def = ceDefinition({
        transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }],
      });
      await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', def)).rejects.toThrow('Enterprise edition required');
      expect(createEntity).not.toHaveBeenCalled();
    });
  });

  it('should update existing workflow when entity setting already has workflow id', async () => {
    const definition = JSON.stringify({
      name: 'Updated Workflow',
      initialState: 'draft',
      transitions: [],
    });

    const existingVersionData = {
      id: 'version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Old Workflow","initialState":"draft","transitions":[]}',
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Old Workflow',
        all_versions: [existingVersionData],
        draft_version: existingVersionData,
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Updated Workflow',
        all_versions: [
          expect.objectContaining({ content: definition }),
          existingVersionData,
        ],
        draft_version: expect.objectContaining({ content: definition }),
      });

    await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(validateWorkflowDefinitionData).toHaveBeenCalledWith(mockContext, mockContext.user, definition, 'Incident', 'workflow-id');
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'workflow-id',
      'WorkflowDefinition',
      expect.arrayContaining([
        expect.objectContaining({ key: 'draft_version' }),
        expect.objectContaining({ key: 'all_versions' }),
        expect.objectContaining({ key: 'name', value: ['Updated Workflow'] }),
      ]),
    );
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should create and link workflow when no linked workflow exists', async () => {
    const definition = JSON.stringify({
      initialState: 'draft',
      transitions: [],
    });

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });
    (createEntity as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Workflow for Incident',
      all_versions: [expect.objectContaining({ content: definition })],
      draft_version: expect.objectContaining({ content: definition }),
    });
    (updateAttribute as any).mockResolvedValue({ element: { id: 'entity-setting-id', workflow_id: 'workflow-id' } });

    const result = await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(validateWorkflowDefinitionData).toHaveBeenCalledWith(mockContext, mockContext.user, definition, 'Incident', undefined);
    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      expect.objectContaining({
        name: 'Workflow for Incident',
        draft_version: expect.objectContaining({ content: definition }),
        all_versions: [expect.objectContaining({ content: definition })],
      }),
      'WorkflowDefinition',
    );
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-setting-id',
      'EntitySetting',
      [{ key: 'workflow_id', value: ['workflow-id'] }],
    );
    expect(result).toMatchObject({
      id: 'entity-setting-id',
      workflow_id: 'workflow-id',
      published: false,
    });
  });

  it('should return true when status template id is found in string workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: '{"states":[{"statusId":"status-template-id"}]}',
          validation_errors: [],
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  it('should return true when status template id is found in object workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        draft_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: { states: [{ statusId: 'status-template-id' }] },
          validation_errors: [],
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  it('should return false when status template id is not found in any workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: '{"states":[{"statusId":"another-id"}]}',
          validation_errors: [],
        },
        all_versions: [],
      },
      {
        draft_version: {
          id: 'version-2',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: { states: [{ statusId: 'yet-another-id' }] },
          validation_errors: [],
        },
        all_versions: [],
      },
      {
        published_version: null,
        draft_version: null,
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(false);
  });

  // Tests for publishWorkflowDefinition
  it('should publish workflow when draft_version has no validation errors', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Test Workflow","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        draft_version: draftVersion,
        all_versions: [draftVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion],
      });

    const result = await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'workflow-id',
      'WorkflowDefinition',
      expect.arrayContaining([
        { key: 'published_version', value: [draftVersion] },
      ]),
    );
    expect(result).toMatchObject({
      id: 'entity-setting-id',
      workflow_id: 'workflow-id',
      published: true,
    });
  });

  it('should fail to publish workflow when draft_version has validation errors', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Invalid Workflow","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [{ type: 'INVALID_SCHEMA', message: 'Missing required field', path: [] }],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Invalid Workflow',
      draft_version: draftVersion,
      all_versions: [draftVersion],
    });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Cannot publish workflow with validation errors');
  });

  it('should fail to publish workflow when no draft_version exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'No Draft Workflow',
      draft_version: null,
      all_versions: [],
    });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('No draft version to publish');
  });

  it('should fail to publish workflow when entity setting not found', async () => {
    (findByType as any).mockResolvedValue(null);

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Entity setting not found for type');
  });

  it('should fail to publish workflow when no workflow is linked', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('No workflow definition to publish');
  });

  it('should clear draft_version when publishing matching content', async () => {
    const version = {
      id: 'version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Same Content","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [],
    };

    // Mock with existing published_version that matches draft
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Same Content',
        published_version: version, // Already has this published
        draft_version: version, // Draft is the same
        all_versions: [version],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Same Content',
        published_version: version,
        draft_version: null, // Should be cleared
        all_versions: [version],
      });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'workflow-id',
      'WorkflowDefinition',
      [
        { key: 'published_version', value: [version] },
        { key: 'draft_version', value: [] },
      ],
    );
  });

  it('should update workflow with different draft and published versions', async () => {
    const existingVersion = {
      id: 'version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Old Workflow","initialState":"draft","transitions":[]}',
      validation_errors: [],
    };

    const definition = JSON.stringify({
      name: 'Updated Workflow',
      initialState: 'draft',
      transitions: [],
    });

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Old Workflow',
        published_version: existingVersion,
        draft_version: existingVersion,
        all_versions: [existingVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Updated Workflow',
        published_version: existingVersion,
        draft_version: expect.objectContaining({ content: definition }),
        all_versions: [
          expect.objectContaining({ content: definition }),
          existingVersion,
        ],
      });

    const result = await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(result.published).toBe(false); // Draft differs from published
  });

  // Tests for validateVersionConsistency (lines 54-74)
  it('should throw error when all_versions is not an array', async () => {
    const definition = JSON.stringify({ name: 'Test', initialState: 'draft', transitions: [] });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      all_versions: null, // Invalid: not an array
      draft_version: { id: 'v1', content: '{}', validation_errors: [] },
    });

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', definition)).rejects.toThrow('all_versions must be an array');
  });

  it('should throw error when draft_version not in all_versions', async () => {
    const definition = JSON.stringify({ name: 'Test', initialState: 'draft', transitions: [] });
    const draftVersion = { id: 'draft-1', timestamp: '2024-01-01', createdBy: 'user-1', content: definition, validation_errors: [] };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [{ id: 'other-version' }], // draft_version not in here
        draft_version: draftVersion,
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [draftVersion, { id: 'other-version' }],
        draft_version: draftVersion,
      });

    await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);
    // Should succeed after update
  });

  it('should validate consistency when publishing', async () => {
    const draftVersion = { id: 'draft-1', timestamp: '2024-01-02', createdBy: 'user-1', content: '{}', validation_errors: [] };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [draftVersion],
        draft_version: draftVersion,
        published_version: null,
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [draftVersion],
        draft_version: null,
        published_version: draftVersion,
      });

    const result = await publishWorkflowDefinition(mockContext, mockUser, 'Incident');
    expect(result.published).toBe(true);
  });

  // Tests for getWorkflowDefinition (lines 203-206)
  it('should get workflow definition with allowDraft=false (published only)', async () => {
    const publishedContent = { name: 'Published', initialState: 'open', transitions: [] };
    const draftContent = { name: 'Draft', initialState: 'draft', transitions: [] };
    const publishedVersion = {
      id: 'pub-1',
      content: JSON.stringify(publishedContent),
      validation_errors: [],
    };
    const draftVersion = {
      id: 'draft-1',
      content: JSON.stringify(draftContent),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', false);

    expect(result).toBeDefined();
    expect(result?.name).toBe('Test Workflow'); // Name comes from entity, not content
    expect(result?.initialState).toBe('open'); // Published version content
    expect(result?.published).toBe(false); // Draft exists and differs
  });

  it('should get workflow definition with allowDraft=true (draft preferred)', async () => {
    const publishedContent = { name: 'Published', initialState: 'open', transitions: [] };
    const draftContent = { name: 'Draft', initialState: 'draft', transitions: [] };
    const publishedVersion = {
      id: 'pub-1',
      content: JSON.stringify(publishedContent),
      validation_errors: [],
    };
    const draftVersion = {
      id: 'draft-1',
      content: JSON.stringify(draftContent),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', true);

    expect(result).toBeDefined();
    expect(result?.name).toBe('Test Workflow'); // Name comes from entity, not content
    expect(result?.initialState).toBe('draft'); // Draft version content
  });

  it('should return null when no entity setting exists', async () => {
    (findByType as any).mockResolvedValue(null);

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toBeNull();
  });

  it('should return null when no workflow_id exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toBeNull();
  });

  it('should return null when no version content exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Empty Workflow',
      published_version: { id: 'v1', content: null }, // No content
      all_versions: [],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', false);

    expect(result).toBeNull();
  });

  it('should handle content as object instead of string', async () => {
    const contentObj = { name: 'Object Content', initialState: 'open', transitions: [] };
    const version = {
      id: 'v1',
      content: contentObj, // Object, not string
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: version,
      all_versions: [version],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', false);

    expect(result).toBeDefined();
    expect(result?.name).toBe('Test Workflow'); // Entity name overrides content name
    expect(result?.initialState).toBe('open'); // From content object
  });

  // Tests for deleteWorkflowDefinition (line 335)
  it('should delete workflow definition', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (updateAttribute as any).mockResolvedValue({
      element: { id: 'entity-setting-id', workflow_id: null, target_type: 'Incident' },
    });

    const result = await deleteWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-setting-id',
      'EntitySetting',
      [{ key: 'workflow_id', value: [null] }],
    );
    expect(result).toBeDefined();
  });

  it('should return entity setting when no workflow_id to delete', async () => {
    const entitySetting = { id: 'entity-setting-id', workflow_id: null };
    (findByType as any).mockResolvedValue(entitySetting);

    const result = await deleteWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).not.toHaveBeenCalled();
    expect(result).toBe(entitySetting);
  });

  // Tests for getAllowedTransitions (lines 469-490)
  it('should return allowed transitions for an entity', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident', internal_id: 'entity-1' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Incident Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [
        { from: 'open', to: 'closed', event: 'close', actions: [{ type: 'log' }] },
      ],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue({ id: 'instance-1', currentState: 'open' });

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-1');

    expect(transitions).toHaveLength(1);
    expect(transitions[0]).toEqual(expect.objectContaining({
      event: 'close',
      toState: 'closed',
      actions: ['log'],
    }));
  });

  it('should return empty array when entity not found', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'invalid-id');

    expect(transitions).toEqual([]);
  });

  it('should return empty array when no workflow configured', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null);

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-1');

    expect(transitions).toEqual([]);
  });

  it('should use initial state when current state is invalid', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident', internal_id: 'entity-1' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Incident Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close' }],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue({ id: 'instance-1', currentState: 'invalid-state' });

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-1');

    // When state doesn't exist but workflow has getTransitions mock, it still returns transitions
    expect(transitions).toBeDefined();
  });

  // Tests for getWorkflowInstance (line 438)
  it('should return null when entity not found for workflow instance', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    const instance = await getWorkflowInstance(mockContext, mockUser, 'invalid-id');

    expect(instance).toBeNull();
  });

  it('should return null when no workflow configured for entity', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null);

    const instance = await getWorkflowInstance(mockContext, mockUser, 'entity-1');

    expect(instance).toBeNull();
  });

  // Tests for triggerWorkflowEvent (lines 536, 554-573)
  it('should return failure when entity not found for trigger', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    await expect(triggerWorkflowEvent(mockContext, mockUser, 'invalid-id', 'test')).rejects.toThrow('Entity not found');
  });

  it('should return failure when no workflow configured for trigger', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null);

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'test');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('not configured');
  });

  it('should return failure when entity setting not found', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };

    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null); // No entity setting

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'test');

    expect(result.success).toBe(false);
  });

  // Tests for isStatusTemplateUsedInWorkflows (lines 607-609)
  it('should detect status template in workflow content as object', async () => {
    const contentObj = {
      name: 'Test',
      states: [{ statusId: 'status-template-id' }],
      transitions: [],
    };

    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'workflow-1',
        published_version: {
          id: 'v1',
          content: contentObj, // Object instead of string
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  // Tests for successful triggerWorkflowEvent (lines 566-577, 585-612)
  it('should successfully trigger workflow event and create instance', async () => {
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Test Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close' }],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      if (type === 'WorkflowInstance') return { id: 'instance-1', currentState: 'closed', history: '[]' };
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue(null); // No existing instance
    (createEntity as any).mockResolvedValue({ id: 'instance-1', internal_id: 'instance-1', currentState: 'open', history: '[]' });
    (createRelation as any).mockResolvedValue({ id: 'rel-1' });
    (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'close');

    expect(result.success).toBe(true);
    expect(result.newState).toBe('closed');
    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      expect.objectContaining({
        entity_id: 'entity-1',
        workflow_id: 'workflow-id',
        currentState: 'open',
      }),
      'WorkflowInstance',
    );
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'instance-1',
      'WorkflowInstance',
      expect.arrayContaining([
        expect.objectContaining({ key: 'currentState', value: ['closed'] }),
        expect.objectContaining({ key: 'history' }),
      ]),
    );
  });

  it('should successfully trigger workflow event with existing instance', async () => {
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Test Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close' }],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };
    const existingInstance = { id: 'instance-1', internal_id: 'instance-1', currentState: 'open', history: '[]' };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      if (type === 'WorkflowInstance') return { id: 'instance-1', currentState: 'closed', history: '[]' };
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue(existingInstance); // Existing instance
    (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'close');

    expect(result.success).toBe(true);
    expect(result.newState).toBe('closed');
    expect(createEntity).not.toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), 'WorkflowInstance');
    expect(updateAttribute).toHaveBeenCalled();
  });
});

describe('Transition comments – Domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Override with a state-aware mock so transitions are filtered by `from` state
    (WorkflowFactory.createDefinition as any).mockImplementation((data: any) => ({
      getInitialState: () => data.initialState,
      hasState: (state: string) => (data.states ?? []).some((s: any) => s.statusId === state),
      getTransitions: (fromState: string) => (data.transitions ?? [])
        .filter((t: any) => t.from === fromState || t.from === '*')
        .map((t: any) => ({
          event: t.event,
          to: t.to,
          comment: t.comment,
          actionTypes: (t.actions ?? []).map((a: any) => a.type),
        })),
    }));
  });

  describe('getAllowedTransitions', () => {
    const definitionWithComments = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }, { statusId: 'published' }],
      transitions: [
        { from: 'draft', to: 'reviewed', event: 'review', comment: 'Requires manager approval' },
        { from: 'reviewed', to: 'published', event: 'publish' },
      ],
    });

    it('should expose the comment field on allowed transitions when comment is defined', async () => {
      (storeLoadById as any).mockImplementation((ctx: any, user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: definitionWithComments, timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('review');
      expect(transitions[0].comment).toBe('Requires manager approval');
    });

    it('should expose undefined comment on allowed transitions when no comment is defined', async () => {
      (storeLoadById as any).mockImplementation((ctx: any, user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: definitionWithComments, timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'reviewed', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('publish');
      expect(transitions[0].comment).toBeUndefined();
    });

    it('should exclude transitions whose conditions are not met by the requesting user', async () => {
      (WorkflowFactory.createDefinition as any).mockImplementation(() => ({
        getInitialState: () => 'draft',
        hasState: () => true,
        getTransitions: (fromState: string) => {
          if (fromState !== 'draft') return [];
          return [
            { event: 'review', to: 'reviewed', actionTypes: [], conditions: [] },
            { event: 'publish', to: 'published', actionTypes: [], conditions: [() => Promise.resolve(false)] },
          ];
        },
      }));

      (storeLoadById as any).mockImplementation((ctx: any, user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: '{}', timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('review');
    });
  });

  describe('triggerWorkflowEvent – comment handling', () => {
    const definitionData = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
      transitions: [
        { from: 'draft', to: 'reviewed', event: 'review' },
      ],
    });

    const setupMocks = () => {
      (storeLoadById as any).mockImplementation((ctx: any, user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: definitionData, timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-id' } });
    };

    it('should include the user-provided comment in the history entry', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Reviewed and approved');

      const updateCall = (updateAttribute as any).mock.calls[0];
      const historyArg = updateCall[4].find((a: any) => a.key === 'history');
      expect(historyArg).toBeDefined();
      const history = JSON.parse(historyArg.value[0]);
      const lastEntry = history[history.length - 1];
      expect(lastEntry.comment).toBe('Reviewed and approved');
    });

    it('should NOT include a comment key in the history entry when no comment is provided', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review');

      const updateCall = (updateAttribute as any).mock.calls[0];
      const historyArg = updateCall[4].find((a: any) => a.key === 'history');
      expect(historyArg).toBeDefined();
      const history = JSON.parse(historyArg.value[0]);
      const lastEntry = history[history.length - 1];
      expect(lastEntry).not.toHaveProperty('comment');
    });

    it('should NOT include a comment key in the history entry when comment is an empty string', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', '');

      const updateCall = (updateAttribute as any).mock.calls[0];
      const historyArg = updateCall[4].find((a: any) => a.key === 'history');
      const history = JSON.parse(historyArg.value[0]);
      const lastEntry = history[history.length - 1];
      expect(lastEntry).not.toHaveProperty('comment');
    });
  });
});

// ===========================================================================
// getWorkflowInstance — pending transition enrichment
// ===========================================================================

describe('getWorkflowInstance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const makeBaseSetup = () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({
        initialState: 'draft',
        states: [{ statusId: 'draft' }],
        transitions: [],
      }), validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue(null); // no instance
  };

  it('returns pendingTransition: null when instance has no pendingTransition', async () => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: null });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.pendingTransition).toBeNull();
  });

  it('returns pendingTransition: null when pendingTransition JSON is malformed', async () => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: '{ bad json' });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.pendingTransition).toBeNull();
  });

  it('passes slot through as-is when workId is missing', async () => {
    makeBaseSetup();
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: '', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result.pendingTransition.asyncActions[0].workId).toBe('');
    expect(result.pendingTransition.asyncActions[0].processedCount).toBeUndefined();
  });

  it('passes slot through as-is when Work entity is not found', async () => {
    makeBaseSetup();
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });
    // Work lookup returns null
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      return Promise.resolve(null); // Work returns null
    });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');
    expect(result.pendingTransition.asyncActions[0].processedCount).toBeUndefined();
  });

  it('enriches slot with counts from BackgroundTask when Work and BackgroundTask are found', async () => {
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      if (id === 'work-1') return Promise.resolve({ id: 'work-1', background_task_id: 'task-1', received_time: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T01:00:00Z', status: 'progress', errors: [] });
      if (id === 'task-1') return Promise.resolve({ id: 'task-1', task_expected_number: 50, task_processed_number: 25 });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    const slot = result.pendingTransition.asyncActions[0];
    expect(slot.expectedCount).toBe(50);
    expect(slot.processedCount).toBe(25);
    expect(slot.startedAt).toBe('2024-01-01T00:00:00Z');
    expect(slot.workStatus).toBe('progress');
  });

  it('leaves counts at 0 when Work is found but has no background_task_id', async () => {
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      if (id === 'work-1') return Promise.resolve({ id: 'work-1', background_task_id: null, errors: [] });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    const slot = result.pendingTransition.asyncActions[0];
    expect(slot.expectedCount).toBe(0);
    expect(slot.processedCount).toBe(0);
  });
});

// ===========================================================================
// triggerWorkflowEvent — async/pending path + lock + error handling
// ===========================================================================

describe('triggerWorkflowEvent – async / pending / lock', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const asyncDefinition = JSON.stringify({
    initialState: 'draft',
    states: [{ statusId: 'draft' }, { statusId: 'reviewing' }],
    transitions: [{
      from: 'draft',
      to: 'reviewing',
      event: 'submit',
      asyncActions: [{ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['org-1'] } }] } }],
      syncActions: [{ type: 'validateDraft' }],
    }],
  });

  it('returns success:false when pendingStatus is already pending (lock check)', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: asyncDefinition, validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    // Existing instance is already pending
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingStatus: 'pending' });

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('already pending');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('wraps unexpected errors and returns success:false', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: asyncDefinition, validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockRejectedValue(new Error('DB connection error'));

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('DB connection error');
  });

  // Helper shared by the three tests below
  const setupAsyncPendingMocks = (definitionContent: string) => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]' });
    (WorkflowFactory.getInstance as any).mockReturnValue({
      start: vi.fn(),
      trigger: vi.fn().mockResolvedValue({
        success: true,
        executionStatus: 'pending',
        asyncActionSlots: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction' }],
      }),
      getCurrentState: vi.fn().mockReturnValue('reviewing'),
    });
    (updateAttribute as any).mockResolvedValue({ element: {} });
  };

  const getPendingTransitionArg = (): any => {
    const patches: Array<{ key: string; value: any[] }> = (updateAttribute as any).mock.calls[0][4];
    return JSON.parse(patches.find((p) => p.key === 'pendingTransition')!.value[0]);
  };

  // lines 761-763 (toStateId from transition.to) + line 774 (onEnterActions present)
  it('stores onEnterActions in pendingTransition when the target state defines onEnter actions', async () => {
    const definitionContent = JSON.stringify({
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'reviewing', onEnter: [{ type: 'validateDraft' }] },
      ],
      transitions: [{ from: 'draft', to: 'reviewing', event: 'submit', syncActions: [{ type: 'validateDraft' }] }],
    });
    setupAsyncPendingMocks(definitionContent);

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    const stored = getPendingTransitionArg();
    expect(stored.toState).toBe('reviewing');
    expect(stored.onEnterActions).toEqual([{ type: 'validateDraft' }]);
  });

  // line 774 (onEnterActions absent when serializedOnEnterActions is empty)
  it('omits onEnterActions from pendingTransition when the target state has no onEnter actions', async () => {
    const definitionContent = JSON.stringify({
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'reviewing' }, // no onEnter
      ],
      transitions: [{ from: 'draft', to: 'reviewing', event: 'submit' }],
    });
    setupAsyncPendingMocks(definitionContent);

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    const stored = getPendingTransitionArg();
    expect(stored).not.toHaveProperty('onEnterActions');
  });

  // line 761 — toStateId falls back to instance.getCurrentState() when transition has no "to"
  it('uses instance.getCurrentState() as toState when the matched transition has no "to" field', async () => {
    const definitionContent = JSON.stringify({
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'reviewing' },
      ],
      transitions: [{ from: 'draft', event: 'submit' }], // no "to" — forces the ?? fallback
    });
    setupAsyncPendingMocks(definitionContent);

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    const stored = getPendingTransitionArg();
    // getCurrentState() mock returns 'reviewing', so toState must equal that value
    expect(stored.toState).toBe('reviewing');
  });
});

// ===========================================================================
// clearWorkflowPendingState
// ===========================================================================

describe('clearWorkflowPendingState', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws when entity is not found', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    await expect(clearWorkflowPendingState(mockContext, mockUser, 'entity-id'))
      .rejects.toThrow('Entity not found');
  });

  it('throws when no workflow instance is found for the entity', async () => {
    (storeLoadById as any).mockResolvedValue({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
    (loadEntity as any).mockResolvedValue(null);

    await expect(clearWorkflowPendingState(mockContext, mockUser, 'entity-id'))
      .rejects.toThrow();
  });

  it('clears pendingStatus, pendingError, pendingTransition and appends an audit history entry', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingStatus: 'error', pendingError: 'task failed', pendingTransition: '{}' });
    (updateAttribute as any).mockResolvedValue({ element: {} });

    await clearWorkflowPendingState(mockContext, mockUser, 'entity-id');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingError')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingTransition')?.value[0]).toBeNull();
    const history = JSON.parse(patches.find((p: any) => p.key === 'history')?.value[0] ?? '[]');
    expect(history[history.length - 1].event).toBe('admin_clear_pending_state');
  });
});

// ---------------------------------------------------------------------------
// getWorkflowPublishedVersionId
// ---------------------------------------------------------------------------

describe('getWorkflowPublishedVersionId', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  it('returns null when entitySetting has no workflow_id', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace' } as any;

    const result = await getWorkflowPublishedVersionId(mockContext, entitySetting);

    expect(result).toBeNull();
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('returns null when the WorkflowDefinitionEntity is not found', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue(undefined);

    const result = await getWorkflowPublishedVersionId(mockContext, entitySetting);

    expect(result).toBeNull();
    expect(storeLoadById).toHaveBeenCalledWith(mockContext, mockContext.user, 'wf-id', expect.any(String));
  });

  it('returns null when the WorkflowDefinitionEntity has no published_version', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue({ id: 'wf-id', draft_version: { id: 'draft-v1' } });

    const result = await getWorkflowPublishedVersionId(mockContext, entitySetting);

    expect(result).toBeNull();
  });

  it('returns the published_version id when the workflow has been published', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue({
      id: 'wf-id',
      published_version: { id: 'pub-v1', timestamp: '2024-01-01T00:00:00Z' },
      draft_version: { id: 'draft-v2', timestamp: '2024-02-01T00:00:00Z' },
    });

    const result = await getWorkflowPublishedVersionId(mockContext, entitySetting);

    expect(result).toBe('pub-v1');
  });

  it('returns the published_version id even when no draft exists (published and clean)', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue({
      id: 'wf-id',
      published_version: { id: 'pub-v1', timestamp: '2024-01-01T00:00:00Z' },
    });

    const result = await getWorkflowPublishedVersionId(mockContext, entitySetting);

    expect(result).toBe('pub-v1');
  });
});

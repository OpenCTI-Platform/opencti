import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import * as Middleware from '../../../../src/database/middleware';
import * as BackgroundTask from '../../../../src/domain/backgroundTask';
import * as Redis from '../../../../src/database/redis';
import * as UserActionListener from '../../../../src/listener/UserActionListener';
import * as Access from '../../../../src/utils/access';
import { EditOperation, FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import {
  customFieldDefinitionAdd,
  customFieldDefinitionAddEntityType,
  customFieldDefinitionDelete,
  customFieldDefinitionEdit,
  customFieldDefinitionRemoveEntityType,
  customFieldDefinitionUpdateEntityType,
  findById,
  findCustomFieldDefinitionByName,
  findCustomFieldDefinitionsForEntityType,
  findCustomFieldDefinitionsPaginated,
  isCustomFieldKey,
  loadCustomFieldDefinitions,
} from '../../../../src/modules/customField/custom-field-domain';
import { getCustomFieldDefinitionByName, setCustomFieldDefinitionsCache } from '../../../../src/modules/customField/custom-field-cache';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';

vi.mock('../../../../src/database/middleware-loader', () => ({
  countAllThings: vi.fn(),
  fullEntitiesList: vi.fn(async () => []),
  pageEntitiesConnection: vi.fn(async () => ({ edges: [], pageInfo: {} })),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../../src/domain/backgroundTask', () => ({
  createQueryTask: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn().mockImplementation((_topic, element) => Promise.resolve(element)),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/utils/access', async () => {
  const actual = await vi.importActual('../../../../src/utils/access') as object;
  return {
    ...actual,
    enforceEnableFeatureFlag: vi.fn(),
    executionContext: vi.fn(() => ({ source: 'testing' })),
  };
});

const mockContext = { source: 'testing' } as any;
const mockUser = { id: 'user-1' } as any;

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  standard_id: 'custom-field-definition--id-1',
  entity_type: 'CustomFieldDefinition',
  name: 'x_opencti_cf_field',
  label: 'Field',
  description: '',
  field_type: 'string',
  entity_types: [],
  entity_type_settings: [],
  multiple: false,
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

beforeEach(() => {
  // resetAllMocks (not clearAllMocks) so a mockImplementation set by one test (e.g. making
  // enforceEnableFeatureFlag throw) never leaks into the next test.
  vi.resetAllMocks();
  setCustomFieldDefinitionsCache([]);
  vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
  vi.mocked(MiddlewareLoader.pageEntitiesConnection).mockResolvedValue({ edges: [], pageInfo: {} } as any);
  vi.mocked(Redis.notify).mockImplementation((_topic: string, element: any) => Promise.resolve(element));
  vi.mocked(Access.executionContext).mockReturnValue({ source: 'testing' } as any);
});

describe('isCustomFieldKey', () => {
  it('returns true for keys prefixed with the custom field prefix', () => {
    expect(isCustomFieldKey('x_opencti_cf_score')).toBe(true);
  });

  it('returns false for keys not prefixed with the custom field prefix', () => {
    expect(isCustomFieldKey('name')).toBe(false);
  });
});

describe('findById / findCustomFieldDefinitionsPaginated / findCustomFieldDefinitionsForEntityType', () => {
  it('findById delegates to storeLoadById with the CustomFieldDefinition type', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(makeDefinition() as any);
    await findById(mockContext, mockUser, 'cf-id-1');
    expect(MiddlewareLoader.storeLoadById).toHaveBeenCalledWith(mockContext, mockUser, 'cf-id-1', 'CustomFieldDefinition');
  });

  it('findCustomFieldDefinitionsPaginated delegates to pageEntitiesConnection', async () => {
    const opts = { first: 10 } as any;
    await findCustomFieldDefinitionsPaginated(mockContext, mockUser, opts);
    expect(MiddlewareLoader.pageEntitiesConnection).toHaveBeenCalledWith(mockContext, mockUser, ['CustomFieldDefinition'], opts);
  });

  it('findCustomFieldDefinitionsForEntityType builds an entity_types filter', async () => {
    await findCustomFieldDefinitionsForEntityType(mockContext, mockUser, 'Case-Incident');
    expect(MiddlewareLoader.pageEntitiesConnection).toHaveBeenCalledWith(mockContext, mockUser, ['CustomFieldDefinition'], {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['entity_types'], values: ['Case-Incident'], operator: FilterOperator.Eq }],
        filterGroups: [],
      },
    });
  });

  it('findCustomFieldDefinitionByName returns the node when found', async () => {
    const def = makeDefinition({ name: 'x_opencti_cf_field' });
    vi.mocked(MiddlewareLoader.pageEntitiesConnection).mockResolvedValue({ edges: [{ node: def }], pageInfo: {} } as any);
    const result = await findCustomFieldDefinitionByName(mockContext, mockUser, 'x_opencti_cf_field');
    expect(result).toEqual(def);
  });

  it('findCustomFieldDefinitionByName returns null when not found', async () => {
    vi.mocked(MiddlewareLoader.pageEntitiesConnection).mockResolvedValue({ edges: [], pageInfo: {} } as any);
    const result = await findCustomFieldDefinitionByName(mockContext, mockUser, 'x_opencti_cf_unknown');
    expect(result).toBeNull();
  });
});

describe('loadCustomFieldDefinitions', () => {
  it('fetches all definitions and populates the cache', async () => {
    const defs = [makeDefinition()];
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue(defs as any);
    await loadCustomFieldDefinitions(mockContext);
    expect(MiddlewareLoader.fullEntitiesList).toHaveBeenCalledWith(mockContext, Access.SYSTEM_USER, ['CustomFieldDefinition']);
    expect(getCustomFieldDefinitionByName(defs[0].name)).toEqual(defs[0]);
  });
});

describe('customFieldDefinitionAdd', () => {
  const validInput = {
    name: 'x_opencti_cf_score',
    label: 'Score',
    field_type: 'integer',
  } as any;

  it('throws when the feature flag is disabled', async () => {
    vi.mocked(Access.enforceEnableFeatureFlag).mockImplementation(() => {
      throw new Error('feature disabled');
    });
    await expect(customFieldDefinitionAdd(mockContext, mockUser, validInput)).rejects.toThrow('feature disabled');
    expect(Middleware.createEntity).not.toHaveBeenCalled();
  });

  it('throws on an invalid technical name', async () => {
    await expect(customFieldDefinitionAdd(mockContext, mockUser, { ...validInput, name: 'invalid_name' }))
      .rejects.toThrow('Technical name must start with "x_opencti_cf_"');
    expect(Middleware.createEntity).not.toHaveBeenCalled();
  });

  it('throws when the technical name already exists', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_score' })]);
    await expect(customFieldDefinitionAdd(mockContext, mockUser, validInput))
      .rejects.toThrow('A custom field with this technical name already exists');
  });

  it('throws when the label already exists', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_other', label: 'Score' })]);
    await expect(customFieldDefinitionAdd(mockContext, mockUser, validInput))
      .rejects.toThrow('A custom field with this label already exists');
  });

  it('throws on an unsupported field_type', async () => {
    await expect(customFieldDefinitionAdd(mockContext, mockUser, { ...validInput, field_type: 'unsupported' }))
      .rejects.toThrow('Unsupported custom field type');
  });

  it('throws when min_value is greater than max_value', async () => {
    await expect(customFieldDefinitionAdd(mockContext, mockUser, { ...validInput, min_value: 10, max_value: 5 }))
      .rejects.toThrow('min_value cannot be greater than max_value');
  });

  it('throws when select_options is missing for a select field', async () => {
    await expect(customFieldDefinitionAdd(mockContext, mockUser, { ...validInput, field_type: 'select', select_options: [] }))
      .rejects.toThrow('select_options must be provided');
  });

  it('creates the entity, forces multiple=true for multi_select, notifies and publishes the user action', async () => {
    const created = { id: 'cf-id-1', name: 'x_opencti_cf_tags' };
    vi.mocked(Middleware.createEntity).mockResolvedValue(created as any);
    const input = { ...validInput, name: 'x_opencti_cf_tags', field_type: 'multi_select', select_options: ['a', 'b'], multiple: false };
    await customFieldDefinitionAdd(mockContext, mockUser, input);
    expect(Middleware.createEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ multiple: true }),
      'CustomFieldDefinition',
    );
    expect(UserActionListener.publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      event_scope: 'create',
      message: 'creates custom field definition `x_opencti_cf_tags`',
    }));
    expect(MiddlewareLoader.fullEntitiesList).toHaveBeenCalled();
    expect(Redis.notify).toHaveBeenCalledWith(expect.any(String), created, mockUser);
  });
});

describe('customFieldDefinitionDelete', () => {
  it('deletes the entity, notifies, publishes the action, reloads the cache and schedules the cascade cleanup', async () => {
    const element = { id: 'cf-id-1', name: 'x_opencti_cf_score', entity_types: ['Case-Incident'] };
    vi.mocked(Middleware.deleteElementById).mockResolvedValue(element as any);

    await customFieldDefinitionDelete(mockContext, mockUser, 'cf-id-1');

    expect(Middleware.deleteElementById).toHaveBeenCalledWith(mockContext, mockUser, 'cf-id-1', 'CustomFieldDefinition');
    expect(Redis.notify).toHaveBeenCalledWith(expect.any(String), element, mockUser);
    expect(UserActionListener.publishUserAction).toHaveBeenCalledWith(expect.objectContaining({ event_scope: 'delete' }));
    expect(MiddlewareLoader.fullEntitiesList).toHaveBeenCalled();
    expect(BackgroundTask.createQueryTask).toHaveBeenCalledWith(
      expect.anything(),
      Access.SYSTEM_USER,
      expect.objectContaining({
        filters: expect.stringContaining('x_opencti_cf_score'),
      }),
    );
  });
});

describe('customFieldDefinitionEdit', () => {
  it('throws when trying to edit an immutable key (field_type or name)', async () => {
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', [{ key: 'field_type', value: ['string'] } as any]))
      .rejects.toThrow('Cannot modify immutable fields');
    expect(Middleware.updateAttribute).not.toHaveBeenCalled();
  });

  it('throws when the new label is already used by another definition', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ id: 'cf-id-2', label: 'Existing label' })]);
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', [{ key: 'label', value: ['Existing label'] } as any]))
      .rejects.toThrow('A custom field with this label already exists');
  });

  it('does not throw when editing the label to the same value on the same definition', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ id: 'cf-id-1', label: 'Same label' })]);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: makeDefinition({ id: 'cf-id-1' }) } as any);
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', [{ key: 'label', value: ['Same label'] } as any]))
      .resolves.not.toThrow();
  });

  it('throws when removing a select option still used by existing entities', async () => {
    const definition = makeDefinition({ field_type: 'select', select_options: ['a', 'b'] });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(MiddlewareLoader.countAllThings).mockResolvedValue(3);
    const edit = [{ key: 'select_options', value: ['a'], operation: EditOperation.Replace } as any];
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', edit))
      .rejects.toThrow('Cannot remove a select option that is still used');
    expect(Middleware.updateAttribute).not.toHaveBeenCalled();
  });

  it('allows removing a select option not used by any entity', async () => {
    const definition = makeDefinition({ field_type: 'select', select_options: ['a', 'b'] });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(MiddlewareLoader.countAllThings).mockResolvedValue(0);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: definition } as any);
    const edit = [{ key: 'select_options', value: ['a'], operation: EditOperation.Replace } as any];
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', edit)).resolves.not.toThrow();
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });

  it('throws when tightening min_value beyond an already-stored value', async () => {
    const definition = makeDefinition({ field_type: 'integer', min_value: 0, max_value: 100 });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(MiddlewareLoader.countAllThings).mockResolvedValue(2);
    const edit = [{ key: 'min_value', value: ['10'] } as any];
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', edit))
      .rejects.toThrow('Cannot restrict the value range');
    expect(Middleware.updateAttribute).not.toHaveBeenCalled();
  });

  it('allows tightening min_value when no stored value falls out of bounds', async () => {
    const definition = makeDefinition({ field_type: 'integer', min_value: 0, max_value: 100 });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(MiddlewareLoader.countAllThings).mockResolvedValue(0);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: definition } as any);
    const edit = [{ key: 'min_value', value: ['10'] } as any];
    await expect(customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', edit)).resolves.not.toThrow();
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });

  it('updates the attribute, notifies, publishes the action and reloads the cache on success', async () => {
    const updatedElem = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_score' });
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: updatedElem } as any);
    const edit = [{ key: 'description', value: ['New description'] } as any];
    await customFieldDefinitionEdit(mockContext, mockUser, 'cf-id-1', edit);
    expect(Middleware.updateAttribute).toHaveBeenCalledWith(mockContext, mockUser, 'cf-id-1', 'CustomFieldDefinition', edit);
    expect(UserActionListener.publishUserAction).toHaveBeenCalledWith(expect.objectContaining({ event_scope: 'update' }));
    expect(MiddlewareLoader.fullEntitiesList).toHaveBeenCalled();
    expect(Redis.notify).toHaveBeenCalledWith(expect.any(String), updatedElem, mockUser);
  });
});

describe('customFieldDefinitionAddEntityType', () => {
  it('throws when the definition does not exist', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(null as any);
    await expect(customFieldDefinitionAddEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident', true))
      .rejects.toThrow('Custom field definition not found');
  });

  it('attaches the entity type with its mandatory/default_value settings', async () => {
    const definition = makeDefinition({ entity_types: [], entity_type_settings: [] });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: definition } as any);
    await customFieldDefinitionAddEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident', true, '5');
    expect(Middleware.updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'cf-id-1',
      'CustomFieldDefinition',
      [
        { key: 'entity_types', value: ['Case-Incident'], operation: EditOperation.Replace },
        { key: 'entity_type_settings', value: [{ entity_type: 'Case-Incident', mandatory: true, default_value: '5' }], operation: EditOperation.Replace },
      ],
    );
  });
});

describe('customFieldDefinitionUpdateEntityType', () => {
  it('throws when the definition does not exist', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(null as any);
    await expect(customFieldDefinitionUpdateEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident', true))
      .rejects.toThrow('Custom field definition not found');
  });

  it('throws when the definition is not currently attached to the entity type', async () => {
    const definition = makeDefinition({ entity_types: ['Report'] });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    await expect(customFieldDefinitionUpdateEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident', true))
      .rejects.toThrow('Custom field definition is not attached to this entity type');
  });

  it('updates the settings for an already-attached entity type', async () => {
    const definition = makeDefinition({ entity_types: ['Case-Incident'], entity_type_settings: [{ entity_type: 'Case-Incident', mandatory: false }] });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: definition } as any);
    await customFieldDefinitionUpdateEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident', true, '10');
    expect(Middleware.updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'cf-id-1',
      'CustomFieldDefinition',
      [{ key: 'entity_type_settings', value: [{ entity_type: 'Case-Incident', mandatory: true, default_value: '10' }], operation: EditOperation.Replace }],
    );
  });
});

describe('customFieldDefinitionRemoveEntityType', () => {
  it('throws when the definition does not exist', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(null as any);
    await expect(customFieldDefinitionRemoveEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident'))
      .rejects.toThrow('Custom field definition not found');
  });

  it('detaches the entity type, updates settings and schedules the cleanup task scoped to that entity type', async () => {
    const definition = makeDefinition({
      name: 'x_opencti_cf_score',
      entity_types: ['Case-Incident', 'Report'],
      entity_type_settings: [{ entity_type: 'Case-Incident', mandatory: true }, { entity_type: 'Report', mandatory: false }],
    });
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(definition as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: definition } as any);

    await customFieldDefinitionRemoveEntityType(mockContext, mockUser, 'cf-id-1', 'Case-Incident');

    expect(Middleware.updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'cf-id-1',
      'CustomFieldDefinition',
      [
        { key: 'entity_types', value: ['Report'], operation: EditOperation.Replace },
        { key: 'entity_type_settings', value: [{ entity_type: 'Report', mandatory: false }], operation: EditOperation.Replace },
      ],
    );
    expect(BackgroundTask.createQueryTask).toHaveBeenCalledWith(
      expect.anything(),
      Access.SYSTEM_USER,
      expect.objectContaining({ filters: expect.stringContaining('"Case-Incident"') }),
    );
  });
});

import { describe, expect, it, vi, beforeEach } from 'vitest';
import customFieldResolvers from '../../../../src/modules/customField/custom-field-resolvers';
import * as customFieldDomain from '../../../../src/modules/customField/custom-field-domain';

vi.mock('../../../../src/modules/customField/custom-field-domain', () => ({
  findById: vi.fn(),
  findCustomFieldDefinitionsPaginated: vi.fn(),
  findCustomFieldDefinitionsForEntityType: vi.fn(),
  customFieldDefinitionAdd: vi.fn(),
  customFieldDefinitionDelete: vi.fn(),
  customFieldDefinitionEdit: vi.fn(),
  customFieldDefinitionAddEntityType: vi.fn(),
  customFieldDefinitionUpdateEntityType: vi.fn(),
  customFieldDefinitionRemoveEntityType: vi.fn(),
}));

const mockContext = { user: { id: 'user-id' } } as any;
// Resolver fields are typed as the generated union (function | { resolve }); tests invoke them directly.
const Query = customFieldResolvers.Query as any;
const Mutation = customFieldResolvers.Mutation as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Query.customFieldDefinition resolver', () => {
  it('forwards to findById with the context user and id', () => {
    vi.mocked(customFieldDomain.findById).mockReturnValue('definition' as any);
    const result = Query.customFieldDefinition({}, { id: 'cf-1' }, mockContext, {} as any);
    expect(customFieldDomain.findById).toHaveBeenCalledWith(mockContext, mockContext.user, 'cf-1');
    expect(result).toBe('definition');
  });
});

describe('Query.customFieldDefinitions resolver', () => {
  it('forwards to findCustomFieldDefinitionsPaginated with the context user and args', () => {
    const args = { first: 10 };
    vi.mocked(customFieldDomain.findCustomFieldDefinitionsPaginated).mockReturnValue('connection' as any);
    const result = Query.customFieldDefinitions({}, args as any, mockContext, {} as any);
    expect(customFieldDomain.findCustomFieldDefinitionsPaginated).toHaveBeenCalledWith(mockContext, mockContext.user, args);
    expect(result).toBe('connection');
  });
});

describe('Query.customFieldDefinitionsForEntityType resolver', () => {
  it('forwards to findCustomFieldDefinitionsForEntityType with the context user and entityType', () => {
    vi.mocked(customFieldDomain.findCustomFieldDefinitionsForEntityType).mockReturnValue(['def'] as any);
    const result = Query.customFieldDefinitionsForEntityType({}, { entityType: 'Case-Incident' }, mockContext, {} as any);
    expect(customFieldDomain.findCustomFieldDefinitionsForEntityType).toHaveBeenCalledWith(mockContext, mockContext.user, 'Case-Incident');
    expect(result).toEqual(['def']);
  });
});

describe('Mutation.customFieldDefinitionAdd resolver', () => {
  it('forwards to customFieldDefinitionAdd with the context user and input', async () => {
    const input = { name: 'x_opencti_cf_test', label: 'Test', field_type: 'string' } as any;
    vi.mocked(customFieldDomain.customFieldDefinitionAdd).mockResolvedValue('created' as any);
    const result = await Mutation.customFieldDefinitionAdd({}, { input }, mockContext, {} as any);
    expect(customFieldDomain.customFieldDefinitionAdd).toHaveBeenCalledWith(mockContext, mockContext.user, input);
    expect(result).toBe('created');
  });
});

describe('Mutation.customFieldDefinitionDelete resolver', () => {
  it('forwards to customFieldDefinitionDelete with the context user and id', async () => {
    vi.mocked(customFieldDomain.customFieldDefinitionDelete).mockResolvedValue('cf-1' as any);
    const result = await Mutation.customFieldDefinitionDelete({}, { id: 'cf-1' }, mockContext, {} as any);
    expect(customFieldDomain.customFieldDefinitionDelete).toHaveBeenCalledWith(mockContext, mockContext.user, 'cf-1');
    expect(result).toBe('cf-1');
  });
});

describe('Mutation.customFieldDefinitionFieldPatch resolver', () => {
  it('forwards to customFieldDefinitionEdit with the context user, id and input', async () => {
    const input = [{ key: 'label', value: ['New label'] }] as any;
    vi.mocked(customFieldDomain.customFieldDefinitionEdit).mockResolvedValue('edited' as any);
    const result = await Mutation.customFieldDefinitionFieldPatch({}, { id: 'cf-1', input }, mockContext, {} as any);
    expect(customFieldDomain.customFieldDefinitionEdit).toHaveBeenCalledWith(mockContext, mockContext.user, 'cf-1', input);
    expect(result).toBe('edited');
  });
});

describe('Mutation.customFieldDefinitionAddEntityType resolver', () => {
  it('forwards to customFieldDefinitionAddEntityType with the context user and args', async () => {
    vi.mocked(customFieldDomain.customFieldDefinitionAddEntityType).mockResolvedValue('updated' as any);
    const result = await Mutation.customFieldDefinitionAddEntityType(
      {},
      { id: 'cf-1', entityType: 'Case-Incident', mandatory: true, default_value: 'default' },
      mockContext,
      {} as any,
    );
    expect(customFieldDomain.customFieldDefinitionAddEntityType).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'cf-1',
      'Case-Incident',
      true,
      'default',
    );
    expect(result).toBe('updated');
  });
});

describe('Mutation.customFieldDefinitionUpdateEntityType resolver', () => {
  it('forwards to customFieldDefinitionUpdateEntityType with the context user and args', async () => {
    vi.mocked(customFieldDomain.customFieldDefinitionUpdateEntityType).mockResolvedValue('updated' as any);
    const result = await Mutation.customFieldDefinitionUpdateEntityType(
      {},
      { id: 'cf-1', entityType: 'Case-Incident', mandatory: false, default_value: null },
      mockContext,
      {} as any,
    );
    expect(customFieldDomain.customFieldDefinitionUpdateEntityType).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'cf-1',
      'Case-Incident',
      false,
      null,
    );
    expect(result).toBe('updated');
  });
});

describe('Mutation.customFieldDefinitionRemoveEntityType resolver', () => {
  it('forwards to customFieldDefinitionRemoveEntityType with the context user and args', async () => {
    vi.mocked(customFieldDomain.customFieldDefinitionRemoveEntityType).mockResolvedValue('updated' as any);
    const result = await Mutation.customFieldDefinitionRemoveEntityType(
      {},
      { id: 'cf-1', entityType: 'Case-Incident' },
      mockContext,
      {} as any,
    );
    expect(customFieldDomain.customFieldDefinitionRemoveEntityType).toHaveBeenCalledWith(mockContext, mockContext.user, 'cf-1', 'Case-Incident');
    expect(result).toBe('updated');
  });
});

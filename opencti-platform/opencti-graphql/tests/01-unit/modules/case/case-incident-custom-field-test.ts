import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Middleware from '../../../../src/database/middleware';
import * as Redis from '../../../../src/database/redis';
import * as CacheModule from '../../../../src/database/cache';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(async (_ctx, _user, input) => ({ ...input, id: 'created-id', standard_id: 'std-id', entity_type: 'Case-Incident' })),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  internalLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn().mockImplementation((_topic, element) => Promise.resolve(element)),
  BUS_TOPICS: {},
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(async () => []),
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
    isFeatureEnabled: vi.fn(() => true),
  };
});

vi.mock('../../../../src/domain/user', () => ({
  resolveUserIndividual: vi.fn(async () => 'individual-id'),
}));

vi.mock('../../../../src/modules/case/case-domain', () => ({
  upsertTemplateForCase: vi.fn(async () => ({})),
}));

vi.mock('../../../../src/utils/access', () => ({
  enforceEnableFeatureFlag: vi.fn(),
  executionContext: vi.fn(() => ({})),
  SYSTEM_USER: { id: 'system' },
}));

const MOCK_CONTEXT = {} as any;
const MOCK_USER = { id: 'user-1' } as any;

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  standard_id: 'custom-field-definition--id-1',
  entity_type: 'CustomFieldDefinition',
  name: 'x_opencti_cf_score',
  label: 'Score',
  description: '',
  field_type: 'integer',
  entity_types: ['Case-Incident'],
  entity_type_settings: [{ entity_type: 'Case-Incident', mandatory: false }],
  multiple: false,
  min_value: 0,
  max_value: 100,
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

describe('addCaseIncident — custom field values handling', () => {
  const seed = (...definitions: BasicStoreEntityCustomFieldDefinition[]) => {
    vi.mocked(CacheModule.getEntitiesListFromCache).mockResolvedValue(definitions);
  };

  beforeEach(() => {
    vi.clearAllMocks();
    seed();
    vi.mocked(Middleware.createEntity).mockResolvedValue({ id: 'created-id', entity_type: 'Case-Incident' } as any);
    vi.mocked(Redis.notify).mockImplementation((_t, el) => Promise.resolve(el));
  });

  it('does not resolve custom_field_values at domain layer, letting middleware layer handle it', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_score', field_type: 'integer' }));
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, {
      name: 'Test',
      customFieldValues: [{ field_name: 'x_opencti_cf_score', value: [42] }],
    } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.custom_field_values).toBeUndefined();
  });

  it('forward the camelCase customFieldValues key before calling createEntity', async () => {
    seed(makeDefinition());
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, {
      name: 'Test',
      customFieldValues: [{ field_name: 'x_opencti_cf_score', value: [5] }],
    } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.customFieldValues).toEqual([
      expect.objectContaining({ field_name: 'x_opencti_cf_score', value: [5] }),
    ]);
  });

  it('does not set custom_field_values on the entity when no values are provided', async () => {
    seed(makeDefinition());
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, { name: 'Test' } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.customFieldValues).toBeUndefined();
    expect(callArg.custom_field_values).toBeUndefined();
  });
});

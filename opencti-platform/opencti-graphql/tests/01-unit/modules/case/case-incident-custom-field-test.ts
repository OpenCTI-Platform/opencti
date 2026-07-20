import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Middleware from '../../../../src/database/middleware';
import * as Redis from '../../../../src/database/redis';
import { setCustomFieldDefinitionsCache } from '../../../../src/modules/customField/custom-field-cache';
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
  beforeEach(() => {
    setCustomFieldDefinitionsCache([]);
    vi.clearAllMocks();
    vi.mocked(Middleware.createEntity).mockResolvedValue({ id: 'created-id', entity_type: 'Case-Incident' } as any);
    vi.mocked(Redis.notify).mockImplementation((_t, el) => Promise.resolve(el));
  });

  it('stores normalized custom field values on the entity when feature is enabled and values are provided', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_score', field_type: 'integer' })]);
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, {
      name: 'Test',
      customFieldValues: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_score', int_value: 42 }],
    } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.custom_field_values).toEqual([
      expect.objectContaining({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_score', int_value: 42 }),
    ]);
  });

  it('removes the camelCase customFieldValues key before calling createEntity', async () => {
    setCustomFieldDefinitionsCache([makeDefinition()]);
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, {
      name: 'Test',
      customFieldValues: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_score', int_value: 5 }],
    } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.customFieldValues).toBeUndefined();
  });

  it('does not set custom_field_values on the entity when no values are provided', async () => {
    setCustomFieldDefinitionsCache([makeDefinition()]);
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, { name: 'Test' } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.custom_field_values).toBeUndefined();
  });

  it('rejects an integer value out of bounds via validateCustomFieldValues', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_score', field_type: 'integer', min_value: 0, max_value: 100 })]);
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await expect(
      addCaseIncident(MOCK_CONTEXT, MOCK_USER, {
        name: 'Test',
        customFieldValues: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_score', int_value: 999 }],
      } as any),
    ).rejects.toThrow('int_value is above maximum');
  });

  it('normalizes null GraphQL fields to undefined in the CustomFieldValue shape', async () => {
    setCustomFieldDefinitionsCache([makeDefinition({ field_type: 'integer' })]);
    const { addCaseIncident } = await import('../../../../src/modules/case/case-incident/case-incident-domain');

    await addCaseIncident(MOCK_CONTEXT, MOCK_USER, {
      name: 'Test',
      customFieldValues: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_score', int_value: 10, string_value: null, boolean_value: null }],
    } as any);

    const callArg = vi.mocked(Middleware.createEntity).mock.calls[0][2] as any;
    expect(callArg.custom_field_values[0].string_value).toBeUndefined();
    expect(callArg.custom_field_values[0].boolean_value).toBeUndefined();
    expect(callArg.custom_field_values[0].int_value).toBe(10);
  });
});

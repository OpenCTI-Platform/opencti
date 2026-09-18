import { describe, expect, it, vi, beforeEach } from 'vitest';
import { buildMaterializeOptions, materializeEntityFromFields } from '../../../../src/modules/form/form-entity-materializer';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../../src/modules/grouping/grouping-types';
import type { FormFieldDefinition } from '../../../../src/modules/form/form-types';
import { FormFieldType } from '../../../../src/modules/form/form-types';

vi.mock('../../../../src/modules/form/form-entity-builder', () => ({
  completeEntity: vi.fn((entityType: string, entity: Record<string, unknown>) => ({
    ...entity,
    entity_type: entityType,
    standard_id: 'standard--fake',
    internal_id: 'internal-fake',
    id: 'internal-fake',
  })),
}));

vi.mock('../../../../src/modules/form/form-fields-converter', () => ({
  convertFieldType: vi.fn((value: unknown) => value),
  transformSpecialFields: vi.fn(async (_c: unknown, _u: unknown, entity: Record<string, unknown>) => entity),
}));

vi.mock('../../../../src/database/utils', () => ({
  isEmptyField: (value: unknown) => value === undefined || value === null || value === '',
}));

vi.mock('../../../../src/schema/stixCyberObservable', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/schema/stixCyberObservable')>();
  return {
    ...actual,
    isStixCyberObservable: (type: string) => type === 'IPv4-Addr',
  };
});

vi.mock('../../../../src/utils/syntax', () => ({
  checkObservableSyntax: vi.fn(() => true),
}));

const context = {} as never;
const user = {} as never;

const makeField = (name: string, attributeName: string, overrides: Partial<FormFieldDefinition> = {}): FormFieldDefinition => ({
  id: name,
  name,
  label: name,
  type: FormFieldType.Text,
  required: false,
  attributeMapping: { entity: 'main_entity', attributeName },
  isReadOnly: false,
  defaultValue: undefined,
  ...overrides,
});

describe('materializeEntityFromFields', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('applies fields and keeps empty values when skipEmptyFieldValues is false', async () => {
    const fields = [makeField('name', 'name'), makeField('description', 'description')];
    const values: Record<string, unknown> = { name: 'Cobalt Strike', description: '' };

    const entity = await materializeEntityFromFields(
      context,
      user,
      'Malware',
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.name).toBe('Cobalt Strike');
    expect(entity.description).toBe('');
  });

  it('skips empty field values when skipEmptyFieldValues is true', async () => {
    const fields = [makeField('name', 'name'), makeField('description', 'description')];
    const values: Record<string, unknown> = { name: 'Cobalt Strike', description: '' };

    const entity = await materializeEntityFromFields(
      context,
      user,
      'Malware',
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: true, isBypass: false, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.name).toBe('Cobalt Strike');
    expect(entity.description).toBeUndefined();
  });

  it('does not skip empty arrays or objects when skipEmptyFieldValues is true', async () => {
    const fields = [makeField('aliases', 'aliases'), makeField('details', 'details')];
    const values: Record<string, unknown> = { aliases: [], details: {} };

    const entity = await materializeEntityFromFields(
      context,
      user,
      'Report',
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: true, isBypass: false, applyTypeDefaults: false, errorLabel: 'test error' },
    );

    expect(entity.aliases).toEqual([]);
    expect((entity as unknown as Record<string, unknown>).details).toEqual({});
  });

  it('does not apply fields when applyFields is false, but still seeds and completes', async () => {
    const fields = [makeField('name', 'name')];

    const entity = await materializeEntityFromFields(
      context,
      user,
      'IPv4-Addr',
      fields,
      () => 'unused',
      {
        seedEntity: { value: '1.2.3.4' },
        applyFields: false,
        skipEmptyFieldValues: true,
        isBypass: false,
        applyTypeDefaults: false,
        errorLabel: 'test error',
      },
    );

    expect(entity.name).toBeUndefined();
    expect(entity.value).toBe('1.2.3.4');
  });

  it('merges seedEntity before applying fields', async () => {
    const fields = [makeField('name', 'name')];
    const values: Record<string, unknown> = { name: 'override' };

    const entity = await materializeEntityFromFields(
      context,
      user,
      'IPv4-Addr',
      fields,
      (field) => values[field.name],
      {
        seedEntity: { pattern_type: 'stix' },
        applyFields: true,
        skipEmptyFieldValues: true,
        isBypass: false,
        applyTypeDefaults: false,
        errorLabel: 'test error',
      },
    );

    expect(entity.pattern_type).toBe('stix');
    expect(entity.name).toBe('override');
  });

  it('uses defaultValue for read-only fields when not bypassing', async () => {
    const fields = [makeField('name', 'name', { isReadOnly: true, defaultValue: 'Locked Name' })];

    const entity = await materializeEntityFromFields(
      context,
      user,
      'Malware',
      fields,
      () => 'should not be used',
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.name).toBe('Locked Name');
  });

  it('uses resolveFieldValue for read-only fields when bypassing', async () => {
    const fields = [makeField('name', 'name', { isReadOnly: true, defaultValue: 'Locked Name' })];

    const entity = await materializeEntityFromFields(
      context,
      user,
      'Malware',
      fields,
      () => 'Bypass Value',
      { applyFields: true, skipEmptyFieldValues: false, isBypass: true, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.name).toBe('Bypass Value');
  });

  it('defaults is_family to true for malware when not set', async () => {
    const fields = [makeField('name', 'name')];
    const values: Record<string, unknown> = { name: 'Test Malware' };

    const entity = await materializeEntityFromFields(
      context,
      user,
      ENTITY_TYPE_MALWARE,
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.is_family).toBe(true);
  });

  it('does not override is_family for malware when already set', async () => {
    const fields = [makeField('name', 'name'), makeField('is_family', 'is_family')];
    const values: Record<string, unknown> = { name: 'Test Malware', is_family: false };

    const entity = await materializeEntityFromFields(
      context,
      user,
      ENTITY_TYPE_MALWARE,
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.is_family).toBe(false);
  });

  it('defaults context to "form" for grouping when not set', async () => {
    const fields = [makeField('name', 'name')];
    const values: Record<string, unknown> = { name: 'Test Grouping' };

    const entity = await materializeEntityFromFields(
      context,
      user,
      ENTITY_TYPE_CONTAINER_GROUPING,
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: true, errorLabel: 'test error' },
    );

    expect(entity.context).toBe('form');
  });

  it('does not apply type defaults when applyTypeDefaults is false', async () => {
    const fields = [makeField('name', 'name')];
    const values: Record<string, unknown> = { name: 'No defaults' };

    const malware = await materializeEntityFromFields(
      context,
      user,
      ENTITY_TYPE_MALWARE,
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: false, errorLabel: 'test error' },
    );

    const grouping = await materializeEntityFromFields(
      context,
      user,
      ENTITY_TYPE_CONTAINER_GROUPING,
      fields,
      (field) => values[field.name],
      { applyFields: true, skipEmptyFieldValues: false, isBypass: false, applyTypeDefaults: false, errorLabel: 'test error' },
    );

    expect(malware.is_family).toBeUndefined();
    expect(grouping.context).toBeUndefined();
  });

  it('throws a FunctionalError when observable syntax validation fails', async () => {
    const { checkObservableSyntax } = await import('../../../../src/utils/syntax');
    vi.mocked(checkObservableSyntax).mockReturnValueOnce('Valid IPv4 address');

    const fields = [makeField('value', 'value')];
    const values: Record<string, unknown> = { value: 'not-an-ip' };

    await expect(materializeEntityFromFields(
      context,
      user,
      'IPv4-Addr',
      fields,
      (field) => values[field.name],
      {
        applyFields: true,
        skipEmptyFieldValues: false,
        isBypass: false,
        applyTypeDefaults: true,
        errorLabel: 'Main entity observable is not correctly formatted',
      },
    )).rejects.toThrow('Main entity observable is not correctly formatted');
  });
});

describe('buildMaterializeOptions', () => {
  it('applies the shared defaults (applyFields, skipEmptyFieldValues=false, applyTypeDefaults) plus isBypass and errorLabel', () => {
    expect(buildMaterializeOptions(false, { errorLabel: 'boom' })).toEqual({
      applyFields: true,
      skipEmptyFieldValues: false,
      applyTypeDefaults: true,
      isBypass: false,
      errorLabel: 'boom',
    });
  });

  it('forwards isBypass separately from the overrides', () => {
    expect(buildMaterializeOptions(true, { errorLabel: 'boom' }).isBypass).toBe(true);
  });

  it('lets per-call-site overrides win over the shared defaults', () => {
    const seedEntity = { id: 'seed' };
    expect(buildMaterializeOptions(false, {
      seedEntity,
      applyFields: false,
      skipEmptyFieldValues: true,
      applyTypeDefaults: false,
      errorLabel: 'custom label',
    })).toEqual({
      seedEntity,
      applyFields: false,
      skipEmptyFieldValues: true,
      applyTypeDefaults: false,
      isBypass: false,
      errorLabel: 'custom label',
    });
  });
});

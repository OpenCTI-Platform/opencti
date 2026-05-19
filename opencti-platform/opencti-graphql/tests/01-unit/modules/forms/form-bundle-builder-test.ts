import type { StixObject } from '../../../../src/types/stix-2-1-common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';
import { loadFormEntity } from '../../../../src/modules/form/form-utils';
import { convertStoreToStix_2_1 } from '../../../../src/database/stix-2-1-converter';
import { isStixDomainObjectContainer } from '../../../../src/schema/stixDomainObject';
import { refangValues } from '../../../../src/utils/observable';
import { isStixCyberObservable } from '../../../../src/schema/stixCyberObservable';
import { checkObservableSyntax } from '../../../../src/utils/syntax';
import { transformSpecialFields } from '../../../../src/modules/form/form-fields-converter';
import { completeEntity } from '../../../../src/modules/form/form-entity-builder';
import { buildAdditionalEntities, buildMainStixEntities, buildRelationships, wrapInContainerOrPush } from '../../../../src/modules/form/form-bundle-builder';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/modules/form/form-utils', () => ({
  loadFormEntity: vi.fn(),
  convertIdentityClass: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
  internalLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/stix-2-1-converter', () => ({
  convertStoreToStix_2_1: vi.fn((entity: any) => {
    return {
      id: entity.standard_id ?? `stix--${entity.entity_type}`,
      type: entity.entity_type?.toLowerCase() ?? 'unknown',
      ...entity,
    };
  }),
}));

vi.mock('../../../../src/schema/stixDomainObject', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/schema/stixDomainObject')>();
  return {
    ...actual,
    isStixDomainObjectContainer: vi.fn(() => false),
  };
});

vi.mock('../../../../src/database/utils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/database/utils')>();
  return {
    ...actual,
    isEmptyField: vi.fn((v: any) => v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0)),
    isNotEmptyField: vi.fn((v: any) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0)),
  };
});

vi.mock('../../../../src/utils/observable', () => ({
  refangValues: vi.fn((v: string[]) => v),
  detectObservableType: vi.fn(() => 'Domain-Name'),
}));

vi.mock('../../../../src/python/pythonBridge', () => ({
  createStixPattern: vi.fn(async () => "[domain-name:value = 'evil.com']"),
}));

vi.mock('../../../../src/config/errors', () => ({
  FunctionalError: vi.fn((msg: string, data?: any) => {
    const err = new Error(msg);
    Object.assign(err, data);
    return err;
  }),
}));

vi.mock('../../../../src/schema/stixCyberObservable', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/schema/stixCyberObservable')>();
  return {
    ...actual,
    isStixCyberObservable: vi.fn(() => false), // ← override avec un vrai mock
  };
});

vi.mock('../../../../src/utils/syntax', () => ({
  checkObservableSyntax: vi.fn(() => true),
}));

vi.mock('../../../../src/modules/grouping/grouping-types', () => ({
  ENTITY_TYPE_CONTAINER_GROUPING: 'Grouping',
}));

vi.mock('../../../../src/modules/form/form-fields-converter', () => ({
  transformSpecialFields: vi.fn(async (_context: any, _user: any, entity: any) => entity),
  convertFieldType: vi.fn((value: any) => value),
}));

vi.mock('../../../../src/modules/form/form-entity-builder', () => ({
  completeEntity: vi.fn((_type: string, entity: any) => {
    return {
      ...entity,
      standard_id: `${_type.toLowerCase()}--completed-id`,
      internal_id: 'test-internal-id',
      id: 'test-internal-id',
    };
  }),
}));

// ─── Imports après les mocks ──────────────────────────────────────────────────

const context = {} as AuthContext;
const user = SYSTEM_USER;

const makeField = (overrides = {}): any => ({
  id: 'f1',
  name: 'name',
  label: 'Name',
  type: 'text',
  attributeMapping: { entity: 'main_entity', attributeName: 'name' },
  ...overrides,
});

const makeSchema = (overrides = {}): any => ({
  fields: [],
  ...overrides,
});

const makeBundle = () => ({ objects: [] as any[] });

// ─── buildMainStixEntities ────────────────────────────────────────────────────

describe('buildMainStixEntities', () => {
  beforeEach(() => vi.clearAllMocks());
  describe('mainEntityLookup', () => {
    it('should load entity by id and push its stix conversion', async () => {
      const schema = makeSchema({ mainEntityLookup: true });

      vi.mocked(loadFormEntity).mockResolvedValue({ standard_id: 'malware--00000000-0000-0000-0000-000000000001', name: 'Emotet' } as any);
      const values = { mainEntityLookup: 'entity-id-1' };

      const { mainStixEntities, mainEntityStixId } = await buildMainStixEntities(context, user, schema, values, 'Malware');
      expect(loadFormEntity).toHaveBeenCalledWith(context, user, 'entity-id-1', 'Malware');
      expect(mainStixEntities).toHaveLength(1);
      expect(mainEntityStixId).toBe('malware--00000000-0000-0000-0000-000000000001');
    });

    it('should handle an array of lookup ids', async () => {
      vi.mocked(loadFormEntity).mockResolvedValue({ standard_id: 'malware--abc' } as any);

      const schema = makeSchema({ mainEntityLookup: true });
      const values = { mainEntityLookup: ['id-1', 'id-2'] };

      const { mainStixEntities } = await buildMainStixEntities(context, user, schema, values, 'Malware');

      expect(loadFormEntity).toHaveBeenCalledTimes(2);
      expect(mainStixEntities).toHaveLength(2);
    });

    it('should set mainEntityStixId to the last loaded entity standard_id', async () => {
      vi.mocked(loadFormEntity)
        .mockResolvedValueOnce({ standard_id: 'malware--first' } as any)
        .mockResolvedValueOnce({ standard_id: 'malware--last' } as any);

      const schema = makeSchema({ mainEntityLookup: true });
      const values = { mainEntityLookup: ['id-1', 'id-2'] };

      const { mainEntityStixId } = await buildMainStixEntities(context, user, schema, values, 'Malware');

      expect(mainEntityStixId).toBe('malware--last');
    });
  });

  describe('fieldMode: multiple', () => {
    it('should build one entity per group', async () => {
      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'multiple',
        fields: [makeField()],
      });
      const values = { mainEntityGroups: [{ name: 'Malware A' }, { name: 'Malware B' }] };

      const { mainStixEntities } = await buildMainStixEntities(context, user, schema, values, 'Malware');

      expect(mainStixEntities).toHaveLength(2);
    });

    it('should set is_family=true for Malware when is_family is empty', async () => {
      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'multiple',
        fields: [makeField()],
      });
      const values = { mainEntityGroups: [{ name: 'Emotet' }] };

      await buildMainStixEntities(context, user, schema, values, 'Malware');

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.is_family).toBe(true);
    });

    it('should not override is_family when already set', async () => {
      vi.mocked(transformSpecialFields).mockResolvedValueOnce({
        entity_type: 'Malware',
        is_family: false,
      } as any);

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'multiple',
        fields: [makeField()],
      });
      const values = { mainEntityGroups: [{ name: 'Emotet' }] };

      await buildMainStixEntities(context, user, schema, values, 'Malware');

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.is_family).toBe(false);
    });

    it('should set context="form" for Grouping when context is empty', async () => {
      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'multiple',
        fields: [makeField()],
      });
      const values = { mainEntityGroups: [{ name: 'Group A' }] };

      await buildMainStixEntities(context, user, schema, values, 'Grouping');

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.context).toBe('form');
    });

    it('should throw when observable syntax is invalid', async () => {
      vi.mocked(isStixCyberObservable).mockReturnValue(true);
      vi.mocked(checkObservableSyntax).mockReturnValue('Invalid syntax' as any);
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => ({
        ...entity,
        value: 'bad',
        standard_id: 'domain-name--completed-id',
        internal_id: 'test-internal-id',
        id: 'test-internal-id',
      }));

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'multiple',
        fields: [makeField()],
      });
      const values = { mainEntityGroups: [{ name: 'bad' }] };

      await expect(buildMainStixEntities(context, user, schema, values, 'Domain-Name'))
        .rejects.toThrow('Main entity observable is not correctly formatted');
    });

    it('should not throw when observable syntax is valid', async () => {
      vi.mocked(isStixCyberObservable).mockReturnValue(true);
      vi.mocked(checkObservableSyntax).mockReturnValue(true);
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => ({
        ...entity,
        value: 'evil.com',
        standard_id: 'domain-name--completed-id',
        internal_id: 'test-internal-id',
        id: 'test-internal-id',
      }));

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'multiple',
        fields: [makeField()],
      });
      const values = { mainEntityGroups: [{ name: 'evil.com' }] };

      await expect(buildMainStixEntities(context, user, schema, values, 'Domain-Name'))
        .resolves.not.toThrow();
    });
  });

  describe('fieldMode: parsed', () => {
    it('should build one entity per parsed value', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com', 'bad.org']);

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'parsed',
        mainEntityParseFieldMapping: 'value',
        fields: [],
      });
      const values = { mainEntityParsed: ['evil.com', 'bad.org'] };

      const { mainStixEntities } = await buildMainStixEntities(context, user, schema, values, 'Domain-Name');

      expect(mainStixEntities).toHaveLength(2);
    });

    it('should apply autoConvertToStixPattern when configured', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com']);
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => ({
        ...entity,
        standard_id: 'indicator--id',
        id: 'test-id',
      }));

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'parsed',
        mainEntityParseFieldMapping: 'pattern',
        mainEntityAutoConvertToStixPattern: true,
        fields: [],
      });
      const values = { mainEntityParsed: ['evil.com'] };

      const { mainStixEntities } = await buildMainStixEntities(context, user, schema, values, 'Indicator');

      expect(mainStixEntities[0].pattern).toBe("[domain-name:value = 'evil.com']");
      expect(mainStixEntities[0].pattern_type).toBe('stix');
      expect(mainStixEntities[0].x_opencti_main_observable_type).toBe('Domain-Name');
    });

    it('should map the parsed value to the configured field when no autoConvert', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com']);
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => ({
        ...entity,
        standard_id: 'domain-name--id',
        id: 'test-id',
      }));

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'parsed',
        mainEntityParseFieldMapping: 'value',
        mainEntityAutoConvertToStixPattern: false,
        fields: [],
      });
      const values = { mainEntityParsed: ['evil.com'] };

      const { mainStixEntities } = await buildMainStixEntities(context, user, schema, values, 'Domain-Name');

      expect(mainStixEntities[0].value).toBe('evil.com');
    });

    it('should merge mainEntityFields when provided', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com']);

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'parsed',
        mainEntityParseFieldMapping: 'value',
        fields: [makeField({ attributeMapping: { entity: 'main_entity', attributeName: 'name' } })],
      });
      const values = {
        mainEntityParsed: ['evil.com'],
        mainEntityFields: { name: 'My Observable' },
      };

      const { mainStixEntities } = await buildMainStixEntities(context, user, schema, values, 'Domain-Name');

      expect(mainStixEntities).toHaveLength(1);
    });

    it('should skip empty mainEntityFields values', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com']);

      const schema = makeSchema({
        mainEntityMultiple: true,
        mainEntityFieldMode: 'parsed',
        mainEntityParseFieldMapping: 'value',
        fields: [makeField({ attributeMapping: { entity: 'main_entity', attributeName: 'name' } })],
      });
      const values = {
        mainEntityParsed: ['evil.com'],
        mainEntityFields: { name: '' },
      };

      await buildMainStixEntities(context, user, schema, values, 'Domain-Name');

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.name).toBeUndefined();
    });
  });

  describe('simple entity (no lookup, no multiple)', () => {
    it('should build a single entity from flat values', async () => {
      const schema = makeSchema({ fields: [makeField()] });
      const values = { name: 'Emotet' };

      const { mainStixEntities, mainEntityStixId } = await buildMainStixEntities(context, user, schema, values, 'Malware');

      expect(mainStixEntities).toHaveLength(1);
      expect(mainEntityStixId).toBeDefined();
    });

    it('should only map fields belonging to main_entity', async () => {
      const schema = makeSchema({
        fields: [
          makeField({ name: 'name', attributeMapping: { entity: 'main_entity', attributeName: 'name' } }),
          makeField({ id: 'f2', name: 'description', attributeMapping: { entity: 'other_entity', attributeName: 'description' } }),
        ],
      });
      const values = { name: 'Emotet', description: 'should be ignored' };

      await buildMainStixEntities(context, user, schema, values, 'Malware');

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.name).toBe('Emotet');
      expect(entityPassedToComplete.description).toBeUndefined();
    });

    it('should throw when observable syntax is invalid', async () => {
      vi.mocked(isStixCyberObservable).mockReturnValue(true);
      vi.mocked(checkObservableSyntax).mockReturnValue('Invalid syntax' as any);
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => ({
        ...entity,
        value: 'bad-observable',
        standard_id: 'domain-name--completed-id',
        internal_id: 'test-internal-id',
        id: 'test-internal-id',
      }));

      const schema = makeSchema({ fields: [makeField()] });
      const values = { name: 'bad-observable' };

      await expect(buildMainStixEntities(context, user, schema, values, 'Domain-Name'))
        .rejects.toThrow('Main entity observable is not correctly formatted');
    });
  });
});

// ─── buildAdditionalEntities ──────────────────────────────────────────────────

describe('buildAdditionalEntities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(isStixCyberObservable).mockReturnValue(false);
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(false);
    vi.mocked(completeEntity).mockImplementation((_type: string, entity: any) => ({
      ...entity,
      standard_id: `${_type.toLowerCase()}--completed-id`,
      internal_id: 'test-internal-id',
      id: 'test-internal-id',
    }));
  });

  it('should return empty map when no additionalEntities in schema', async () => {
    const result = await buildAdditionalEntities(context, user, makeSchema(), {}, makeBundle());
    expect(result).toEqual({});
  });

  describe('lookup', () => {
    it('should load entity by id and push it to the bundle', async () => {
      vi.mocked(loadFormEntity).mockResolvedValue({ standard_id: 'identity--abc' } as any);
      vi.mocked(convertStoreToStix_2_1).mockReturnValue({ id: 'identity--abc' } as any);

      const schema = makeSchema({
        additionalEntities: [{ id: 'victim', lookup: true, entityType: 'Identity' }],
      });
      const bundle = makeBundle();
      const values = { additional_victim_lookup: 'identity-id-1' };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(1);
      expect(result.victim).toEqual(['identity--abc']);
    });

    it('should handle an array of lookup ids', async () => {
      vi.mocked(loadFormEntity).mockResolvedValue({ standard_id: 'identity--abc' } as any);
      vi.mocked(convertStoreToStix_2_1).mockReturnValue({ id: 'identity--abc' } as any);

      const schema = makeSchema({
        additionalEntities: [{ id: 'victim', lookup: true, entityType: 'Identity' }],
      });
      const bundle = makeBundle();
      const values = { additional_victim_lookup: ['id-1', 'id-2'] };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(2);
      expect(result.victim).toHaveLength(2);
    });

    it('should skip when lookup value is empty', async () => {
      const schema = makeSchema({
        additionalEntities: [{ id: 'victim', lookup: true, entityType: 'Identity' }],
      });
      const bundle = makeBundle();

      const result = await buildAdditionalEntities(context, user, schema, {}, bundle);

      expect(bundle.objects).toHaveLength(0);
      expect(result.victim).toBeUndefined();
    });
  });

  describe('multiple / fieldMode: multiple', () => {
    it('should build one entity per group and push to bundle', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'victim', attributeName: 'name' } })],
        additionalEntities: [{ id: 'victim', lookup: false, multiple: true, fieldMode: 'multiple', entityType: 'Identity' }],
      });
      const bundle = makeBundle();
      const values = { additional_victim_groups: [{ name: 'Victim A' }, { name: 'Victim B' }] };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(2);
      expect(result.victim).toHaveLength(2);
    });

    it('should skip when groups value is empty', async () => {
      const schema = makeSchema({
        fields: [],
        additionalEntities: [{ id: 'victim', lookup: false, multiple: true, fieldMode: 'multiple', entityType: 'Identity' }],
      });
      const bundle = makeBundle();

      const result = await buildAdditionalEntities(context, user, schema, {}, bundle);

      expect(bundle.objects).toHaveLength(0);
      expect(result.victim).toBeUndefined();
    });

    it('should set is_family=true for Malware additional entities', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'mal', attributeName: 'name' } })],
        additionalEntities: [{ id: 'mal', lookup: false, multiple: true, fieldMode: 'multiple', entityType: 'Malware' }],
      });
      const bundle = makeBundle();
      const values = { additional_mal_groups: [{ name: 'Emotet' }] };

      await buildAdditionalEntities(context, user, schema, values, bundle);

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.is_family).toBe(true);
    });

    it('should set context="form" for Grouping additional entities', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'grp', attributeName: 'name' } })],
        additionalEntities: [{ id: 'grp', lookup: false, multiple: true, fieldMode: 'multiple', entityType: 'Grouping' }],
      });
      const bundle = makeBundle();
      const values = { additional_grp_groups: [{ name: 'Group A' }] };

      await buildAdditionalEntities(context, user, schema, values, bundle);

      const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
      expect(entityPassedToComplete.context).toBe('form');
    });

    it('should throw when observable syntax is invalid', async () => {
      vi.mocked(isStixCyberObservable).mockReturnValue(true);
      vi.mocked(checkObservableSyntax).mockReturnValue('Invalid' as any);
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => ({
        ...entity,
        value: 'bad',
        standard_id: 'domain-name--completed-id',
        internal_id: 'test-internal-id',
        id: 'test-internal-id',
      }));

      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'obs', attributeName: 'value' } })],
        additionalEntities: [{ id: 'obs', lookup: false, multiple: true, fieldMode: 'multiple', entityType: 'Domain-Name', label: 'Observable' }],
      });
      const bundle = makeBundle();
      const values = { additional_obs_groups: [{ value: 'bad' }] };

      await expect(buildAdditionalEntities(context, user, schema, values, bundle))
        .rejects.toThrow('Observable Observable is not correctly formatted');
    });
  });

  describe('multiple / fieldMode: parsed', () => {
    it('should build one entity per parsed value', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com', 'bad.org']);

      const schema = makeSchema({
        fields: [],
        additionalEntities: [{
          id: 'observable',
          lookup: false,
          multiple: true,
          fieldMode: 'parsed',
          parseFieldMapping: 'value',
          entityType: 'Domain-Name',
        }],
      });
      const bundle = makeBundle();
      const values = { additional_observable_parsed: ['evil.com', 'bad.org'] };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(2);
      expect(result.observable).toHaveLength(2);
    });

    it('should skip when parsed value is empty', async () => {
      const schema = makeSchema({
        fields: [],
        additionalEntities: [{
          id: 'observable',
          lookup: false,
          multiple: true,
          fieldMode: 'parsed',
          parseFieldMapping: 'value',
          entityType: 'Domain-Name',
        }],
      });
      const bundle = makeBundle();

      const result = await buildAdditionalEntities(context, user, schema, {}, bundle);

      expect(bundle.objects).toHaveLength(0);
      expect(result.observable).toBeUndefined();
    });

    it('should apply autoConvertToStixPattern when configured', async () => {
      vi.mocked(completeEntity).mockImplementationOnce((_type: string, entity: any) => {
        return {
          ...entity,
          standard_id: 'indicator--id',
          id: 'test-id',
        };
      });
      vi.mocked(convertStoreToStix_2_1).mockImplementationOnce((entity: any) => {
        return entity;
      });

      const schema = makeSchema({
        fields: [],
        additionalEntities: [{
          id: 'indicator',
          lookup: false,
          multiple: true,
          fieldMode: 'parsed',
          parseFieldMapping: 'pattern',
          autoConvertToStixPattern: true,
          entityType: 'Indicator',
        }],
      });
      const bundle = makeBundle();
      const values = { additional_indicator_parsed: ['evil.com'] };

      await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects[0].pattern).toBe("[domain-name:value = 'evil.com']");
      expect(bundle.objects[0].pattern_type).toBe('stix');
    });

    it('should merge additional fields when provided', async () => {
      vi.mocked(refangValues).mockReturnValue(['evil.com']);

      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'observable', attributeName: 'name' } })],
        additionalEntities: [{
          id: 'observable',
          lookup: false,
          multiple: true,
          fieldMode: 'parsed',
          parseFieldMapping: 'value',
          entityType: 'Domain-Name',
        }],
      });
      const bundle = makeBundle();
      const values = {
        additional_observable_parsed: ['evil.com'],
        additional_observable_fields: { name: 'My Observable' },
      };

      await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(1);
    });
  });

  describe('single entity', () => {
    it('should skip when entityData is absent', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'victim', attributeName: 'name' } })],
        additionalEntities: [{ id: 'victim', lookup: false, multiple: false, required: false, entityType: 'Identity' }],
      });
      const bundle = makeBundle();

      const result = await buildAdditionalEntities(context, user, schema, {}, bundle);

      expect(bundle.objects).toHaveLength(0);
      expect(result.victim).toBeUndefined();
    });

    it('should skip when no field is filled and entity is not required', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'victim', attributeName: 'name' } })],
        additionalEntities: [{ id: 'victim', lookup: false, multiple: false, required: false, entityType: 'Identity' }],
      });
      const bundle = makeBundle();
      const values = { additional_victim: { name: '' } };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(0);
      expect(result.victim).toBeUndefined();
    });

    it('should build entity when required even if fields are empty', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'victim', attributeName: 'name' } })],
        additionalEntities: [{ id: 'victim', lookup: false, multiple: false, required: true, entityType: 'Identity' }],
      });
      const bundle = makeBundle();
      const values = { additional_victim: {} };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(1);
      expect(result.victim).toHaveLength(1);
    });

    it('should build entity when at least one field is filled', async () => {
      const schema = makeSchema({
        fields: [makeField({ attributeMapping: { entity: 'victim', attributeName: 'name' } })],
        additionalEntities: [{ id: 'victim', lookup: false, multiple: false, required: false, entityType: 'Identity' }],
      });
      const bundle = makeBundle();
      const values = { additional_victim: { name: 'Victim Corp' } };

      const result = await buildAdditionalEntities(context, user, schema, values, bundle);

      expect(bundle.objects).toHaveLength(1);
      expect(result.victim).toHaveLength(1);
    });
  });

  it('should skip field values that are empty string, null or undefined', async () => {
    const schema = makeSchema({
      fields: [
        makeField({ id: 'f1', name: 'name', attributeMapping: { entity: 'victim', attributeName: 'name' } }),
        makeField({ id: 'f2', name: 'description', attributeMapping: { entity: 'victim', attributeName: 'description' } }),
      ],
      additionalEntities: [{ id: 'victim', lookup: false, multiple: false, required: true, entityType: 'Identity' }],
    });
    const bundle = makeBundle();
    const values = { additional_victim: { name: '', description: null } };

    await buildAdditionalEntities(context, user, schema, values, bundle);

    const entityPassedToComplete = vi.mocked(completeEntity).mock.calls[0][1];
    expect(entityPassedToComplete.name).toBeUndefined();
    expect(entityPassedToComplete.description).toBeUndefined();
  });
});

// ─── buildRelationships ───────────────────────────────────────────────────────

describe('buildRelationships', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should return early when no relationships in schema', async () => {
    const bundle = makeBundle();
    await buildRelationships(context, user, makeSchema(), {}, [], {}, bundle);
    expect(bundle.objects).toHaveLength(0);
  });

  it('should return early when relationships array is empty', async () => {
    const schema = makeSchema({ relationships: [] });
    const bundle = makeBundle();
    await buildRelationships(context, user, schema, { relationships: [] }, [], {}, bundle);
    expect(bundle.objects).toHaveLength(0);
  });

  it('should return early when values.relationships is absent', async () => {
    const schema = makeSchema({
      relationships: [{ id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' }],
    });
    const bundle = makeBundle();

    await buildRelationships(context, user, schema, {}, [{ id: 'main--id' }], { victim: ['identity--id'] }, bundle);

    expect(bundle.objects).toHaveLength(0);
  });

  describe('main_entity → additional entity', () => {
    it('should build a relationship from main entity to additional entity', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' }],
      });
      const bundle = makeBundle();
      const mainStixEntities = [{ id: 'malware--main' }];
      const additionalEntitiesMap = { victim: ['identity--victim'] };
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, mainStixEntities, additionalEntitiesMap, bundle);

      expect(bundle.objects).toHaveLength(1);
      expect(bundle.objects[0].relationship_type).toBe('targets');
      expect(bundle.objects[0].source_ref).toBe('malware--main');
      expect(bundle.objects[0].target_ref).toBe('identity--victim');
      expect(bundle.objects[0].id).toMatch(/^relationship--/);
      expect(bundle.objects[0].spec_version).toBe('2.1');
    });

    it('should build N×M relationships for multiple main and additional entities', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' }],
      });
      const bundle = makeBundle();
      const mainStixEntities = [{ id: 'malware--1' }, { id: 'malware--2' }];
      const additionalEntitiesMap = { victim: ['identity--1', 'identity--2'] };
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, mainStixEntities, additionalEntitiesMap, bundle);

      expect(bundle.objects).toHaveLength(4);
    });

    it('should skip when additionalEntitiesMap has no matching entity', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' }],
      });
      const bundle = makeBundle();
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, [{ id: 'malware--main' }], {}, bundle);

      expect(bundle.objects).toHaveLength(0);
    });
  });

  describe('additional entity → main_entity', () => {
    it('should build a relationship from additional entity to main entity', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'victim', toEntity: 'main_entity', relationshipType: 'attributed-to' }],
      });
      const bundle = makeBundle();
      const mainStixEntities = [{ id: 'malware--main' }];
      const additionalEntitiesMap = { victim: ['identity--victim'] };
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, mainStixEntities, additionalEntitiesMap, bundle);

      expect(bundle.objects).toHaveLength(1);
      expect(bundle.objects[0].source_ref).toBe('identity--victim');
      expect(bundle.objects[0].target_ref).toBe('malware--main');
      expect(bundle.objects[0].relationship_type).toBe('attributed-to');
    });

    it('should skip when additionalEntitiesMap has no matching fromEntity', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'victim', toEntity: 'main_entity', relationshipType: 'attributed-to' }],
      });
      const bundle = makeBundle();
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, [{ id: 'malware--main' }], {}, bundle);

      expect(bundle.objects).toHaveLength(0);
    });
  });

  describe('additional entity → additional entity', () => {
    it('should build a relationship between two additional entities', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'victim', toEntity: 'infra', relationshipType: 'uses' }],
      });
      const bundle = makeBundle();
      const additionalEntitiesMap = {
        victim: ['identity--victim'],
        infra: ['infrastructure--infra'],
      };
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, [], additionalEntitiesMap, bundle);

      expect(bundle.objects).toHaveLength(1);
      expect(bundle.objects[0].source_ref).toBe('identity--victim');
      expect(bundle.objects[0].target_ref).toBe('infrastructure--infra');
    });

    it('should build N×M relationships between two additional entity lists', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'victim', toEntity: 'infra', relationshipType: 'uses' }],
      });
      const bundle = makeBundle();
      const additionalEntitiesMap = {
        victim: ['identity--1', 'identity--2'],
        infra: ['infra--1', 'infra--2', 'infra--3'],
      };
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, [], additionalEntitiesMap, bundle);

      expect(bundle.objects).toHaveLength(6);
    });
  });

  describe('relationship metadata', () => {
    it('should generate unique ids for each relationship', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' }],
      });
      const bundle = makeBundle();
      const mainStixEntities = [{ id: 'malware--1' }, { id: 'malware--2' }];
      const additionalEntitiesMap = { victim: ['identity--1'] };
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, mainStixEntities, additionalEntitiesMap, bundle);

      const ids = bundle.objects.map((o: any) => o.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('should set created and modified as valid ISO dates', async () => {
      const schema = makeSchema({
        relationships: [{ id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' }],
      });
      const bundle = makeBundle();
      const values = { relationships: [{ id: 'r1' }] };

      await buildRelationships(context, user, schema, values, [{ id: 'malware--1' }], { victim: ['identity--1'] }, bundle);

      const rel = bundle.objects[0];
      expect(() => new Date(rel.created).toISOString()).not.toThrow();
      expect(() => new Date(rel.modified).toISOString()).not.toThrow();
    });

    it('should build multiple relationship types in a single call', async () => {
      const schema = makeSchema({
        relationships: [
          { id: 'r1', fromEntity: 'main_entity', toEntity: 'victim', relationshipType: 'targets' },
          { id: 'r2', fromEntity: 'main_entity', toEntity: 'infra', relationshipType: 'uses' },
        ],
      });
      const bundle = makeBundle();
      const mainStixEntities = [{ id: 'malware--main' }];
      const additionalEntitiesMap = {
        victim: ['identity--victim'],
        infra: ['infrastructure--infra'],
      };
      const values = { relationships: [{ id: 'r1' }, { id: 'r2' }] };

      await buildRelationships(context, user, schema, values, mainStixEntities, additionalEntitiesMap, bundle);

      expect(bundle.objects).toHaveLength(2);
      expect(bundle.objects.map((o: any) => o.relationship_type)).toContain('targets');
      expect(bundle.objects.map((o: any) => o.relationship_type)).toContain('uses');
    });
  });
});

// ─── wrapInContainerOrPush ────────────────────────────────────────────────────

describe('wrapInContainerOrPush', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should push entities directly when includeInContainer is false', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = makeBundle();
    const mainStixEntities = [{ id: 'report--1' }, { id: 'report--2' }];

    wrapInContainerOrPush('Report', mainStixEntities, bundle, false);

    expect(bundle.objects).toHaveLength(2);
    expect((bundle.objects[0]).object_refs).toBeUndefined();
  });

  it('should push entities directly when entityType is not a container', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(false);

    const bundle = makeBundle();
    const mainStixEntities = [{ id: 'malware--1' }];

    wrapInContainerOrPush('Malware', mainStixEntities, bundle, true);

    expect(bundle.objects).toHaveLength(1);
    expect((bundle.objects[0]).object_refs).toBeUndefined();
  });

  it('should wrap entity as container with object_refs pointing to existing bundle objects', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = { objects: [{ id: 'malware--existing' }] as unknown as StixObject[] };
    const mainStixEntities = [{ id: 'report--1' }];

    wrapInContainerOrPush('Report', mainStixEntities, bundle, true);

    expect(bundle.objects).toHaveLength(2);
    const container = bundle.objects[1];
    expect(container.id).toBe('report--1');
    expect(container.object_refs).toContain('malware--existing');
  });

  it('should set object_refs to all existing bundle objects at time of wrapping', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = { objects: [{ id: 'obj-1' }, { id: 'obj-2' }, { id: 'obj-3' }] as unknown as StixObject[] };
    const mainStixEntities = [{ id: 'report--1' }];

    wrapInContainerOrPush('Report', mainStixEntities, bundle, true);

    const container = bundle.objects[3];
    expect(container.object_refs).toEqual(['obj-1', 'obj-2', 'obj-3']);
  });

  it('should handle multiple main entities as containers, each with the same object_refs', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = { objects: [{ id: 'malware--1' }] as unknown as StixObject[] };
    const mainStixEntities = [{ id: 'report--1' }, { id: 'report--2' }];

    wrapInContainerOrPush('Report', mainStixEntities, bundle, true);

    expect(bundle.objects).toHaveLength(3);
    expect((bundle.objects[1]).object_refs).toContain('malware--1');
    expect((bundle.objects[2]).object_refs).toContain('malware--1');
  });

  it('should handle empty bundle objects when wrapping as container', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = makeBundle();
    const mainStixEntities = [{ id: 'report--1' }];

    wrapInContainerOrPush('Report', mainStixEntities, bundle, true);

    const container = bundle.objects[0];
    expect(container.object_refs).toEqual([]);
  });

  it('should handle empty mainStixEntities without throwing', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = makeBundle();

    expect(() => wrapInContainerOrPush('Report', [], bundle, true)).not.toThrow();
    expect(bundle.objects).toHaveLength(0);
  });

  it('should handle undefined includeInContainer as falsy', () => {
    vi.mocked(isStixDomainObjectContainer).mockReturnValue(true);

    const bundle = makeBundle();
    const mainStixEntities = [{ id: 'report--1' }];

    wrapInContainerOrPush('Report', mainStixEntities, bundle, undefined);

    expect(bundle.objects).toHaveLength(1);
    expect((bundle.objects[0]).object_refs).toBeUndefined();
  });
});

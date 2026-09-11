import { describe, expect, it } from 'vitest';
import {
  convertFormBuilderDataToSchema,
  formatFormSchemaMappingError,
  getAttributesForEntityType,
  getInitialMandatoryFields,
  normalizeDraftAuthorizedMembersDefaults,
  validateFormSchemaMappings,
} from './FormUtils';
import type { FormBuilderData } from './Form.d';
import type { AuthorizedMemberOption } from '../../../../utils/authorizedMembers';

const baseBuilderData: FormBuilderData = {
  name: 'My form',
  description: '',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: false,
  draftDefaults: undefined,
  mainEntityMultiple: false,
  mainEntityLookup: false,
  mainEntityFieldMode: 'multiple',
  mainEntityParseField: 'text',
  mainEntityParseMode: 'comma',
  additionalEntities: [],
  fields: [],
  relationships: [],
  active: true,
};

describe('validateFormSchemaMappings', () => {
  it('returns null when mainEntityFieldMode is not parsed and no additional entities use parsed mode', () => {
    const data: FormBuilderData = { ...baseBuilderData, mainEntityFieldMode: 'multiple', additionalEntities: [] };

    expect(validateFormSchemaMappings(data)).toBeNull();
  });

  it('returns a main-entity-mapping error when mainEntityFieldMode is parsed but mainEntityParseFieldMapping is missing', () => {
    const data: FormBuilderData = {
      ...baseBuilderData,
      mainEntityFieldMode: 'parsed',
      mainEntityParseFieldMapping: undefined,
      additionalEntities: [],
    };

    expect(validateFormSchemaMappings(data)).toEqual({ type: 'main-entity-mapping' });
  });

  it('returns null when mainEntityFieldMode is parsed and mainEntityParseFieldMapping is set', () => {
    const data: FormBuilderData = {
      ...baseBuilderData,
      mainEntityFieldMode: 'parsed',
      mainEntityParseFieldMapping: 'pattern',
      additionalEntities: [],
    };

    expect(validateFormSchemaMappings(data)).toBeNull();
  });

  it('returns an additional-entity-mappings error listing labels of additional entities missing parseFieldMapping', () => {
    const data: FormBuilderData = {
      ...baseBuilderData,
      mainEntityFieldMode: 'multiple',
      additionalEntities: [
        {
          id: 'a1',
          entityType: 'IPv4-Addr',
          label: 'IP Address',
          multiple: false,
          fieldMode: 'parsed',
          parseFieldMapping: undefined,
        },
        {
          id: 'a2',
          entityType: 'Domain-Name',
          label: 'Domain',
          multiple: false,
          fieldMode: 'parsed',
          parseFieldMapping: 'value',
        },
        {
          id: 'a3',
          entityType: 'Url',
          label: 'URL',
          multiple: false,
          fieldMode: 'multiple',
          parseFieldMapping: undefined,
        },
      ],
    };

    expect(validateFormSchemaMappings(data)).toEqual({
      type: 'additional-entity-mappings',
      missingLabels: ['IP Address'],
    });
  });

  it('prioritizes the main-entity-mapping error over additional-entity-mappings errors', () => {
    const data: FormBuilderData = {
      ...baseBuilderData,
      mainEntityFieldMode: 'parsed',
      mainEntityParseFieldMapping: undefined,
      additionalEntities: [
        {
          id: 'a1',
          entityType: 'IPv4-Addr',
          label: 'IP Address',
          multiple: false,
          fieldMode: 'parsed',
          parseFieldMapping: undefined,
        },
      ],
    };

    expect(validateFormSchemaMappings(data)).toEqual({ type: 'main-entity-mapping' });
  });
});

describe('formatFormSchemaMappingError', () => {
  const t_i18n = (message: string) => `translated:${message}`;

  it('formats a main-entity-mapping error with the translated message', () => {
    expect(formatFormSchemaMappingError({ type: 'main-entity-mapping' }, t_i18n))
      .toBe('translated:Map parsed values to attribute is required when using parsed mode');
  });

  it('translates the additional-entity prefix and appends one raw label', () => {
    expect(formatFormSchemaMappingError({
      type: 'additional-entity-mappings',
      missingLabels: ['IP Address'],
    }, t_i18n)).toBe('translated:Map parsed values to attribute is required for: IP Address');
  });

  it('translates the additional-entity prefix and appends multiple raw labels', () => {
    expect(formatFormSchemaMappingError({
      type: 'additional-entity-mappings',
      missingLabels: ['IP Address', 'Domain'],
    }, t_i18n)).toBe('translated:Map parsed values to attribute is required for: IP Address, Domain');
  });
});

describe('normalizeDraftAuthorizedMembersDefaults', () => {
  it('should migrate legacy rules to normalized authorized member options', () => {
    const defaults = normalizeDraftAuthorizedMembersDefaults([
      { type: 'CREATOR' },
      { type: 'AUTHOR_ORG', intersectionGroup: 'group-a' },
    ]);

    expect(defaults).toEqual([
      {
        label: 'Creators',
        value: 'CREATORS',
        type: 'Dynamic options',
        accessRight: 'admin',
        groupsRestriction: [],
      },
      {
        label: 'Author (organization)',
        value: 'AUTHOR',
        type: 'Dynamic options',
        accessRight: 'admin',
        groupsRestriction: [{ label: 'group-a', value: 'group-a' }],
      },
    ]);
  });

  it('should normalize groupsRestriction entries from value/id/string formats', () => {
    const defaults = normalizeDraftAuthorizedMembersDefaults([
      {
        label: 'Member',
        value: 'user-1',
        type: 'User',
        accessRight: 'view',
        groupsRestriction: [{ value: 'g-1' }, { id: 'g-2' }, 'g-3'],
      },
    ]);

    expect(defaults[0].groupsRestriction).toEqual([
      { value: 'g-1', label: 'g-1' },
      { value: 'g-2', label: 'g-2' },
      { value: 'g-3', label: 'g-3' },
    ]);
  });
});

describe('convertFormBuilderDataToSchema', () => {
  it('should normalize and include authorized member defaults in schema draftDefaults', () => {
    const legacyDefaults = [
      {
        type: 'CREATOR',
      },
    ] as unknown as AuthorizedMemberOption[];

    const values: FormBuilderData = {
      ...baseBuilderData,
      draftDefaults: {
        authorizedMembers: {
          enabled: true,
          isEditable: true,
          isRequired: true,
          defaults: legacyDefaults,
        },
      },
    };

    const schema = convertFormBuilderDataToSchema(values);

    expect(schema.draftDefaults?.authorizedMembers?.enabled).toBe(true);
    expect(schema.draftDefaults?.authorizedMembers?.isRequired).toBe(true);
    expect(schema.draftDefaults?.authorizedMembers?.defaults).toEqual([
      {
        label: 'Creators',
        value: 'CREATORS',
        type: 'Dynamic options',
        accessRight: 'admin',
        groupsRestriction: [],
      },
    ]);
  });

  it('should preserve isEditable and isRequired for name with empty defaultValue', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        name: { isEditable: true, isRequired: false, defaultValue: '   ' },
      },
    });
    expect(schema.draftDefaults?.name?.defaultValue).toBe('   ');
    expect(schema.draftDefaults?.name?.isEditable).toBe(true);
  });

  it('should preserve defaultValue, isEditable, and isRequired for name', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        name: { isEditable: true, isRequired: true, defaultValue: 'My Default Name' },
      },
    });
    expect(schema.draftDefaults?.name?.defaultValue).toBe('My Default Name');
    expect(schema.draftDefaults?.name?.isRequired).toBe(true);
  });

  it('should preserve isEditable for description with empty defaultValue', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        description: { isEditable: false, isRequired: false, defaultValue: '' },
      },
    });
    expect(schema.draftDefaults?.description?.isEditable).toBe(false);
  });

  it('should preserve defaultValue and isEditable for description', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        description: { isEditable: true, isRequired: false, defaultValue: 'Default desc' },
      },
    });
    expect(schema.draftDefaults?.description?.defaultValue).toBe('Default desc');
  });

  it('should preserve isEditable for objectAssignee with empty defaults', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        objectAssignee: { isEditable: true, isRequired: false, defaults: [] },
      },
    });
    expect(schema.draftDefaults?.objectAssignee?.isEditable).toBe(true);
    expect(schema.draftDefaults?.objectAssignee?.defaults).toHaveLength(0);
  });

  it('should preserve isEditable, isRequired, and defaults for objectAssignee', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        objectAssignee: {
          isEditable: false,
          isRequired: true,
          defaults: [{ value: 'user-1', label: 'User 1' }],
        },
      },
    });
    // isRequired is false because isEditable is false — a non-editable field cannot be required
    expect(schema.draftDefaults?.objectAssignee?.isRequired).toBe(false);
    expect(schema.draftDefaults?.objectAssignee?.defaults).toHaveLength(1);
  });

  it('should preserve isEditable and defaults for objectParticipant', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        objectParticipant: {
          isEditable: true,
          isRequired: false,
          defaults: [{ value: 'p-1', label: 'Participant 1' }],
        },
      },
    });
    expect(schema.draftDefaults?.objectParticipant?.defaults).toEqual([{ value: 'p-1', label: 'Participant 1' }]);
  });

  it('should include static author config in schema', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        author: {
          type: 'static',
          isEditable: false,
          isRequired: true, // isRequired will be false in output since isEditable is false
          defaultValue: 'identity-99',
          defaultValueLabel: 'My Org',
          defaultValueType: 'Organization',
        },
      },
    });
    expect(schema.draftDefaults?.author?.type).toBe('static');
    expect(schema.draftDefaults?.author?.defaultValue).toBe('identity-99');
    expect(schema.draftDefaults?.author?.defaultValueLabel).toBe('My Org');
    expect(schema.draftDefaults?.author?.defaultValueType).toBe('Organization');
    // isRequired is false because isEditable is false — a non-editable field cannot be required
    expect(schema.draftDefaults?.author?.isRequired).toBe(false);
  });

  it('should include main_entity_author type in schema', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        author: {
          type: 'main_entity_author',
          isEditable: true,
          isRequired: false,
        },
      },
    });
    expect(schema.draftDefaults?.author?.type).toBe('main_entity_author');
  });

  it('should return undefined draftDefaults when not set', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: undefined,
    });
    expect(schema.draftDefaults).toBeUndefined();
  });

  it('should include isReadOnly on field definitions when set', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      fields: [
        {
          id: 'f1',
          name: 'title',
          label: 'Title',
          type: 'text',
          required: false,
          isReadOnly: true,
          attributeMapping: { entity: 'main_entity', attributeName: 'name' },
        },
      ],
    });
    expect(schema.fields[0].isReadOnly).toBe(true);
  });

  it('should not include isReadOnly on field when not set', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      fields: [
        {
          id: 'f1',
          name: 'title',
          label: 'Title',
          type: 'text',
          required: false,
          isReadOnly: false,
          attributeMapping: { entity: 'main_entity', attributeName: 'name' },
        },
      ],
    });
    expect(schema.fields[0].isReadOnly).toBe(false);
  });
});

describe('container content attribute mapping', () => {
  const t_i18n = (key: string) => key;

  const entityTypes = [
    {
      value: 'Case-Incident',
      label: 'Case Incident',
      attributes: [
        {
          value: 'content',
          name: 'content',
          label: 'Content',
          type: 'markdown',
          mandatory: true,
        },
      ],
    },
  ];

  it('should not expose content as an open vocabulary attribute', () => {
    const openVocabAttributes = getAttributesForEntityType('Case-Incident', 'openvocab', entityTypes, t_i18n);

    expect(openVocabAttributes).toEqual([]);
  });

  it('should keep mandatory content field as textarea', () => {
    const mandatoryFields = getInitialMandatoryFields('Case-Incident', entityTypes, t_i18n);

    expect(mandatoryFields).toHaveLength(1);
    expect(mandatoryFields[0].attributeMapping.attributeName).toBe('content');
    expect(mandatoryFields[0].type).toBe('textarea');
  });
});

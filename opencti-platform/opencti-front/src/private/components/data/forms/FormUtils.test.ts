import { describe, expect, it } from 'vitest';
import { convertFormBuilderDataToSchema, normalizeDraftAuthorizedMembersDefaults } from './FormUtils';
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

  it('should produce enabled=false for name when defaultValue is empty or whitespace', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        name: { enabled: false, isEditable: true, isRequired: false, defaultValue: '   ' },
      },
    });
    expect(schema.draftDefaults?.name?.enabled).toBe(false);
  });

  it('should produce enabled=true for name when defaultValue is non-empty', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        name: { enabled: true, isEditable: true, isRequired: true, defaultValue: 'My Default Name' },
      },
    });
    expect(schema.draftDefaults?.name?.enabled).toBe(true);
    expect(schema.draftDefaults?.name?.defaultValue).toBe('My Default Name');
    expect(schema.draftDefaults?.name?.isRequired).toBe(true);
  });

  it('should produce enabled=false for description when defaultValue is empty', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        description: { enabled: false, isEditable: false, isRequired: false, defaultValue: '' },
      },
    });
    expect(schema.draftDefaults?.description?.enabled).toBe(false);
  });

  it('should produce enabled=true for description when defaultValue is non-empty', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        description: { enabled: true, isEditable: true, isRequired: false, defaultValue: 'Default desc' },
      },
    });
    expect(schema.draftDefaults?.description?.enabled).toBe(true);
    expect(schema.draftDefaults?.description?.defaultValue).toBe('Default desc');
  });

  it('should produce enabled=false for objectAssignee when defaults array is empty', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        objectAssignee: { enabled: false, isEditable: true, isRequired: false, defaults: [] },
      },
    });
    expect(schema.draftDefaults?.objectAssignee?.enabled).toBe(false);
  });

  it('should produce enabled=true for objectAssignee when defaults array has entries', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        objectAssignee: {
          enabled: true,
          isEditable: false,
          isRequired: true,
          defaults: [{ value: 'user-1', label: 'User 1' }],
        },
      },
    });
    expect(schema.draftDefaults?.objectAssignee?.enabled).toBe(true);
    // isRequired is false because isEditable is false — a non-editable field cannot be required
    expect(schema.draftDefaults?.objectAssignee?.isRequired).toBe(false);
    expect(schema.draftDefaults?.objectAssignee?.defaults).toHaveLength(1);
  });

  it('should produce enabled=true for objectParticipant when defaults array has entries', () => {
    const schema = convertFormBuilderDataToSchema({
      ...baseBuilderData,
      draftDefaults: {
        objectParticipant: {
          enabled: true,
          isEditable: true,
          isRequired: false,
          defaults: [{ value: 'p-1', label: 'Participant 1' }],
        },
      },
    });
    expect(schema.draftDefaults?.objectParticipant?.enabled).toBe(true);
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

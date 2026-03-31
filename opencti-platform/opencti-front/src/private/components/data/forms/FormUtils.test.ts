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
});

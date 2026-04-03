import { describe, it, expect } from 'vitest';
import { formatFormDataForSubmission } from './FormViewUtils';
import { FormSchemaDefinition } from '../Form.d';

type SubmissionValues = Parameters<typeof formatFormDataForSubmission>[0];

const baseSchema: FormSchemaDefinition = {
  version: '2.0',
  mainEntityType: 'Report',
  additionalEntities: [],
  relationships: [],
  fields: [
    {
      id: 'name',
      name: 'name',
      label: 'Name',
      type: 'text',
      required: true,
      attributeMapping: {
        entity: 'main_entity',
        attributeName: 'name',
      },
    },
  ],
};

describe('formatFormDataForSubmission', () => {
  it('should include draftName as empty string when explicitly provided empty', () => {
    const values = {
      name: 'My report',
      draftName: '   ',
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).toHaveProperty('draftName', '');
  });

  it('should not include draftName when draftName is omitted', () => {
    const values = {
      name: 'My report',
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).not.toHaveProperty('draftName');
  });

  it('should include draftAuthorizedMembers when explicitly provided as empty array', () => {
    const values = {
      name: 'My report',
      draftAuthorizedMembers: [],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).toHaveProperty('draftAuthorizedMembers');
    expect(formatted.draftAuthorizedMembers).toEqual([]);
  });

  it('should include draftAuthorizedMembers when provided with members', () => {
    const values = {
      name: 'My report',
      draftAuthorizedMembers: [
        {
          value: 'user-1',
          accessRight: 'admin',
          groupsRestriction: [{ value: 'group-1' }],
        },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted.draftAuthorizedMembers).toEqual(values.draftAuthorizedMembers);
  });
});

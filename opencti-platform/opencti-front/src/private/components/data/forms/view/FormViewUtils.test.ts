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

  it('should normalize draftObjectAssignee to an ID array', () => {
    const values = {
      name: 'My report',
      draftObjectAssignee: [
        { value: 'assignee-1', label: 'Assignee 1' },
        { id: 'assignee-2', label: 'Assignee 2' },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted.draftObjectAssignee).toEqual(['assignee-1', 'assignee-2']);
  });

  it('should normalize draftObjectParticipant to an ID array', () => {
    const values = {
      name: 'My report',
      draftObjectParticipant: [
        { value: 'participant-1', label: 'Participant 1' },
        { id: 'participant-2', label: 'Participant 2' },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted.draftObjectParticipant).toEqual(['participant-1', 'participant-2']);
  });

  it('should include draftDescription when present', () => {
    const values = {
      name: 'My report',
      draftDescription: '  My description  ',
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).toHaveProperty('draftDescription', 'My description');
  });

  it('should not include draftDescription when omitted', () => {
    const values = {
      name: 'My report',
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).not.toHaveProperty('draftDescription');
  });

  it('should include draftDescription as empty string when explicitly whitespace', () => {
    const values = {
      name: 'My report',
      draftDescription: '   ',
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).toHaveProperty('draftDescription', '');
  });

  it('should extract draftAuthor id from object', () => {
    const values = {
      name: 'My report',
      draftAuthor: { value: 'identity-1', label: 'Org A' },
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted.draftAuthor).toBe('identity-1');
  });

  it('should set draftAuthor to null when value is null (explicit opt-out signal)', () => {
    const values = {
      name: 'My report',
      draftAuthor: null,
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).toHaveProperty('draftAuthor', null);
  });

  it('should set draftAuthor to null when object has no value property (explicit opt-out signal)', () => {
    const values = {
      name: 'My report',
      draftAuthor: { label: 'No value field' },
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).toHaveProperty('draftAuthor', null);
  });

  it('should not include draftAuthor key when draftAuthor is absent from values', () => {
    const values = {
      name: 'My report',
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, baseSchema);

    expect(formatted).not.toHaveProperty('draftAuthor');
  });
});

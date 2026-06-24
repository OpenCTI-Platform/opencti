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

// ---------------------------------------------------------------------------
// mainEntityLookup – deferred (pending) creation
// ---------------------------------------------------------------------------

const lookupSchema: FormSchemaDefinition = {
  ...baseSchema,
  mainEntityLookup: true,
  mainEntityMultiple: false,
};

const lookupMultiSchema: FormSchemaDefinition = {
  ...baseSchema,
  mainEntityLookup: true,
  mainEntityMultiple: true,
};

describe('formatFormDataForSubmission – mainEntityLookup', () => {
  it('should map a single existing entity to mainEntityLookup', () => {
    const values = {
      name: 'My report',
      mainEntityLookup: { value: 'entity-id-1', label: 'Existing Entity', type: 'Report' },
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, lookupSchema);

    expect(formatted.mainEntityLookup).toBe('entity-id-1');
    expect(formatted).not.toHaveProperty('mainEntityLookupPending');
  });

  it('should map a single pending entity to mainEntityLookupPending', () => {
    const pendingInputData = { entityType: 'Report', input: { name: 'New Report', confidence: 50 } };
    const values = {
      name: 'My report',
      mainEntityLookup: {
        value: '__pending__:some-uuid',
        label: 'New Report',
        type: 'Report',
        isPendingCreation: true,
        pendingInputData,
      },
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, lookupSchema);

    expect(formatted).not.toHaveProperty('mainEntityLookup');
    expect(formatted.mainEntityLookupPending).toEqual([pendingInputData]);
  });

  it('should split multiple existing entities from pending entities', () => {
    const pendingInputData = { entityType: 'Report', input: { name: 'Pending Report' } };
    const values = {
      name: 'My report',
      mainEntityLookup: [
        { value: 'existing-id-1', label: 'Existing 1', type: 'Report' },
        { value: '__pending__:uuid-1', label: 'Pending 1', type: 'Report', isPendingCreation: true, pendingInputData },
        { value: 'existing-id-2', label: 'Existing 2', type: 'Report' },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, lookupMultiSchema);

    expect(formatted.mainEntityLookup).toEqual(['existing-id-1', 'existing-id-2']);
    expect(formatted.mainEntityLookupPending).toEqual([pendingInputData]);
  });

  it('should not produce mainEntityLookupPending when all entities are existing (multiple)', () => {
    const values = {
      name: 'My report',
      mainEntityLookup: [
        { value: 'existing-id-1', label: 'Existing 1', type: 'Report' },
        { value: 'existing-id-2', label: 'Existing 2', type: 'Report' },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, lookupMultiSchema);

    expect(formatted.mainEntityLookup).toEqual(['existing-id-1', 'existing-id-2']);
    expect(formatted).not.toHaveProperty('mainEntityLookupPending');
  });

  it('should not produce mainEntityLookup when all entities are pending (multiple)', () => {
    const pendingInputData1 = { entityType: 'Report', input: { name: 'Pending 1' } };
    const pendingInputData2 = { entityType: 'Report', input: { name: 'Pending 2' } };
    const values = {
      name: 'My report',
      mainEntityLookup: [
        { value: '__pending__:uuid-1', label: 'Pending 1', type: 'Report', isPendingCreation: true, pendingInputData: pendingInputData1 },
        { value: '__pending__:uuid-2', label: 'Pending 2', type: 'Report', isPendingCreation: true, pendingInputData: pendingInputData2 },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, lookupMultiSchema);

    expect(formatted).not.toHaveProperty('mainEntityLookup');
    expect(formatted.mainEntityLookupPending).toEqual([pendingInputData1, pendingInputData2]);
  });
});

// ---------------------------------------------------------------------------
// additional_${id}_lookup – deferred (pending) creation
// ---------------------------------------------------------------------------

const additionalLookupSchema: FormSchemaDefinition = {
  ...baseSchema,
  additionalEntities: [
    {
      id: 'threat',
      entityType: 'Malware',
      label: 'Threat',
      multiple: false,
      lookup: true,
    } as unknown as FormSchemaDefinition['additionalEntities'][0],
  ],
};

const additionalLookupMultiSchema: FormSchemaDefinition = {
  ...baseSchema,
  additionalEntities: [
    {
      id: 'threat',
      entityType: 'Malware',
      label: 'Threat',
      multiple: true,
      lookup: true,
    } as unknown as FormSchemaDefinition['additionalEntities'][0],
  ],
};

describe('formatFormDataForSubmission – additional_${id}_lookup', () => {
  it('should map a single existing entity to additional_threat_lookup', () => {
    const values = {
      name: 'My report',
      additional_threat_lookup: { value: 'malware-id-1', label: 'Evil', type: 'Malware' },
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, additionalLookupSchema);

    expect(formatted['additional_threat_lookup']).toBe('malware-id-1');
    expect(formatted).not.toHaveProperty('additional_threat_lookup_pending');
  });

  it('should map a single pending entity to additional_threat_lookup_pending', () => {
    const pendingInputData = { entityType: 'Malware', input: { name: 'New Malware' } };
    const values = {
      name: 'My report',
      additional_threat_lookup: {
        value: '__pending__:uuid-m',
        label: 'New Malware',
        type: 'Malware',
        isPendingCreation: true,
        pendingInputData,
      },
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, additionalLookupSchema);

    expect(formatted).not.toHaveProperty('additional_threat_lookup');
    expect(formatted['additional_threat_lookup_pending']).toEqual([pendingInputData]);
  });

  it('should split existing and pending entities for multiple lookup', () => {
    const pendingInputData = { entityType: 'Malware', input: { name: 'Pending Malware' } };
    const values = {
      name: 'My report',
      additional_threat_lookup: [
        { value: 'malware-id-1', label: 'Existing', type: 'Malware' },
        { value: '__pending__:uuid-m', label: 'Pending', type: 'Malware', isPendingCreation: true, pendingInputData },
      ],
    };

    const formatted = formatFormDataForSubmission(values as SubmissionValues, additionalLookupMultiSchema);

    expect(formatted['additional_threat_lookup']).toEqual(['malware-id-1']);
    expect(formatted['additional_threat_lookup_pending']).toEqual([pendingInputData]);
  });
});

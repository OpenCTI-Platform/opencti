import { describe, it, expect } from 'vitest';
import { getLevel, parseError } from '@components/data/connectors/parseWorkErrors';

describe('Function: getLevel', () => {
  it('should return Critical', () => {
    expect(getLevel('ELEMENT_ID_COLLISION')).toEqual('Critical');
  });

  it('should return Warning', () => {
    expect(getLevel('INCORRECT_INDICATOR_FORMAT')).toEqual('Warning');
  });

  it('should return Unclassified', () => {
    expect(getLevel('OTHER_ERROR')).toEqual('Unclassified');
  });
});

describe('Function: parseError', () => {
  it('should return a full parsed error with an entity', () => {
    expect(parseError({
      timestamp: '2024-10-11T20:10:06.700Z',
      message: '{\'name\': \'INTERNAL_SERVER_ERROR\', \'error_message\': \'Test error report\'}',
      sequence: null,
      source: '{"type": "report", "spec_version": "2.1", "id": "report--423ae31f-5344-55de-970b-cc902b3d0000"}',
    })).toEqual({
      isParsed: true,
      level: 'Critical',
      parsedError: {
        category: 'INTERNAL_SERVER_ERROR',
        doc_code: 'INTERNAL_SERVER_ERROR',
        message: 'Test error report',
        entity: {
          standard_id: 'report--423ae31f-5344-55de-970b-cc902b3d0000',
          representative: { main: 'report--423ae31f-5344-55de-970b-cc902b3d0000' },
          from: undefined,
          to: undefined,
        },
      },
      rawError: {
        timestamp: '2024-10-11T20:10:06.700Z',
        message: '{\'name\': \'INTERNAL_SERVER_ERROR\', \'error_message\': \'Test error report\'}',
        sequence: null,
        source: '{"type": "report", "spec_version": "2.1", "id": "report--423ae31f-5344-55de-970b-cc902b3d0000"}',
      },
    });
  });

  it('should return a full parsed error with a relationship', () => {
    expect(parseError({
      timestamp: '2024-10-11T20:10:06.708Z',
      message: '{\'name\': \'UNSUPPORTED_ERROR\', \'error_message\': \'Test error relationship\', \'doc_code\': \'RESTRICTED_ELEMENT\'}',
      sequence: null,
      source: '{"type": "relationship", "spec_version": "2.1", "id": "relationship--3bb06e4f-0702-40da-a7db-3ae8e8800000", "created_by_ref": "identity--180d3ffd-a014-54ff-a817-211dddd00000", "created": "2024-10-11T17:19:43.689008Z", "modified": "2024-10-11T17:19:43.689008Z", "relationship_type": "originates-from", "source_ref": "intrusion-set--826cb3d9-0de3-5af7-9e95-f64fa1000000", "target_ref": "location--efa1b9b0-dc59-5bad-baa2-4fc495e00000", "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0000"], "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}',
    })).toEqual({
      isParsed: true,
      level: 'Warning',
      parsedError: {
        category: 'UNSUPPORTED_ERROR',
        doc_code: 'RESTRICTED_ELEMENT',
        message: 'Test error relationship',
        entity: {
          standard_id: 'relationship--3bb06e4f-0702-40da-a7db-3ae8e8800000',
          representative: { main: 'relationship--3bb06e4f-0702-40da-a7db-3ae8e8800000' },
          from: {
            standard_id: 'intrusion-set--826cb3d9-0de3-5af7-9e95-f64fa1000000',
          },
          to: {
            standard_id: 'location--efa1b9b0-dc59-5bad-baa2-4fc495e00000',
          },
        },
      },
      rawError: {
        timestamp: '2024-10-11T20:10:06.708Z',
        message: '{\'name\': \'UNSUPPORTED_ERROR\', \'error_message\': \'Test error relationship\', \'doc_code\': \'RESTRICTED_ELEMENT\'}',
        sequence: null,
        source: '{"type": "relationship", "spec_version": "2.1", "id": "relationship--3bb06e4f-0702-40da-a7db-3ae8e8800000", "created_by_ref": "identity--180d3ffd-a014-54ff-a817-211dddd00000", "created": "2024-10-11T17:19:43.689008Z", "modified": "2024-10-11T17:19:43.689008Z", "relationship_type": "originates-from", "source_ref": "intrusion-set--826cb3d9-0de3-5af7-9e95-f64fa1000000", "target_ref": "location--efa1b9b0-dc59-5bad-baa2-4fc495e00000", "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0000"], "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}',
      },
    });
  });

  it('should return a full parsed error with a bundle', () => {
    expect(parseError({
      timestamp: '2024-10-11T20:10:06.788Z',
      message: '{\'name\': \'MISSING_REFERENCE_ERROR\', \'error_message\': \'Element(s) not found [with bundle]\', \'doc_code\': \'ELEMENT_NOT_FOUND\'}',
      sequence: null,
      source: '{"type": "bundle", "id": "bundle--3d4b0539-a7c0-45b5-8f3f-edebe4000000", "spec_version": "2.1", "x_opencti_seq": 8, "objects": [{"type": "relationship", "spec_version": "2.1", "id": "relationship--41ea9593-cfc4-5d4b-b31d-ca9e4dd00000", "relationship_type": "targets", "source_ref": "malware--fc7e8c2e-6aa7-55cf-9f29-69c66d800000", "target_ref": "identity--f67fbf06-f3cd-58b3-bad9-ed0b45800000", "nb_deps": 8}]}',
    })).toEqual({
      isParsed: true,
      level: 'Warning',
      parsedError: {
        category: 'MISSING_REFERENCE_ERROR',
        doc_code: 'ELEMENT_NOT_FOUND',
        message: 'Element(s) not found [with bundle]',
        entity: {
          standard_id: 'relationship--41ea9593-cfc4-5d4b-b31d-ca9e4dd00000',
          representative: { main: 'relationship--41ea9593-cfc4-5d4b-b31d-ca9e4dd00000' },
          from: {
            standard_id: 'malware--fc7e8c2e-6aa7-55cf-9f29-69c66d800000',
          },
          to: {
            standard_id: 'identity--f67fbf06-f3cd-58b3-bad9-ed0b45800000',
          },
        },
      },
      rawError: {
        timestamp: '2024-10-11T20:10:06.788Z',
        message: '{\'name\': \'MISSING_REFERENCE_ERROR\', \'error_message\': \'Element(s) not found [with bundle]\', \'doc_code\': \'ELEMENT_NOT_FOUND\'}',
        sequence: null,
        source: '{"type": "bundle", "id": "bundle--3d4b0539-a7c0-45b5-8f3f-edebe4000000", "spec_version": "2.1", "x_opencti_seq": 8, "objects": [{"type": "relationship", "spec_version": "2.1", "id": "relationship--41ea9593-cfc4-5d4b-b31d-ca9e4dd00000", "relationship_type": "targets", "source_ref": "malware--fc7e8c2e-6aa7-55cf-9f29-69c66d800000", "target_ref": "identity--f67fbf06-f3cd-58b3-bad9-ed0b45800000", "nb_deps": 8}]}',
      },
    });
  });

  it('should return a partial parsed error', () => {
    expect(parseError({
      timestamp: '2024-10-11T20:10:06.788Z',
      message: '[This message can\'t be parsed]',
      sequence: null,
      source: '{"type": "report", "spec_version": "2.1", "id": "report--423ae31f-5344-55de-970b-cc902b3d0000"}',
    })).toEqual({
      isParsed: false,
      level: 'Unclassified',
      rawError: {
        timestamp: '2024-10-11T20:10:06.788Z',
        message: '[This message can\'t be parsed]',
        sequence: null,
        source: '{"type": "report", "spec_version": "2.1", "id": "report--423ae31f-5344-55de-970b-cc902b3d0000"}',
      },
    });
  });

  it('should manage null value', () => {
    expect(parseError({
      timestamp: null,
      message: null,
      sequence: null,
      source: null,
    })).toEqual({
      isParsed: false,
      level: 'Unclassified',
      rawError: {
        timestamp: null,
        message: null,
        sequence: null,
        source: null,
      },
    });
  });
});

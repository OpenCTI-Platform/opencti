import { describe, expect, it } from 'vitest';
import { validateDataBeforeIndexing } from '../../../src/schema/schema-attributes';

describe('validateDataBeforeIndexing', () => {
  const malware = {
    _index: 'opencti_stix_domain_objects-000001',
    internal_id: '3f9d5688-25e1-427f-8eff-a92110f87ca3',
    entity_type: 'Malware',
    representative: {
      main: 'Agent Racoon'
    },
    is_family: true,
    updated_at: '2024-02-23T09:43:39.913Z',
    modified: '2024-02-23T09:43:39.913Z'
  };

  const threatActorIndividual = {
    _index: 'opencti_stix_domain_objects-000001',
    internal_id: 'ba7b01e7-78f9-45da-8a75-33e41257c255',
    entity_type: 'Threat-Actor-Individual',
    representative: {
      main: 'Jhon Threat Actor Individual',
      secondary: 'This organized threat actor individual.'
    },
    height: [
      {
        measure: 1.2192,
        date_seen: '2024-02-15T23:00:00.000Z'
      }
    ],
    updated_at: '2024-02-23T09:53:26.245Z',
    modified: '2024-02-23T09:53:26.245Z'
  };

  const user = {
    _index: 'opencti_internal_objects-000001',
    internal_id: '421781aa-52cb-4019-abf1-3f8c3c8617bd',
    entity_type: 'User',
    representative: {
      main: 'Plop'
    },
    user_confidence_level: {
      max_confidence: 73, // missing mandatory field in a single object
      overrides: [
        {
          max_confidence: 77,
          entity_type: 'Report'
        }
      ]
    },
    updated_at: '2024-02-23T09:57:32.006Z'
  };

  it('validates correct payloads', () => {
    expect(() => validateDataBeforeIndexing(malware)).not.toThrowError();
    expect(() => validateDataBeforeIndexing(threatActorIndividual)).not.toThrowError();
    expect(() => validateDataBeforeIndexing(user)).not.toThrowError();
  });

  it('throws error on invalid payloads', () => {
    let invalidUser: any = {
      ...user,
      entity_type: undefined,
    };
    expect(() => validateDataBeforeIndexing(invalidUser))
      .toThrowError('Validation against schema failed: element has no entity_type');

    invalidUser = {
      ...user,
      entity_type: 'Wrong',
    };
    expect(() => validateDataBeforeIndexing(invalidUser))
      .toThrowError('Validation against schema failed: this entity_type is not supported');

    invalidUser = {
      ...user,
      user_confidence_level: {
        // max_confidence: 73, // missing mandatory field in a single object
        overrides: [{
          max_confidence: 77,
          entity_type: 'Report'
        }]
      },
    };
    expect(() => validateDataBeforeIndexing(invalidUser))
      .toThrowError('Validation against schema failed on attribute [user_confidence_level]: mandatory field [max_confidence] is not present');

    invalidUser = {
      ...user,
      user_confidence_level: {
        max_confidence: 73,
        overrides: [{
          max_confidence: 77,
          // entity_type: 'Report' // missing mandatory field in a inner multiple object
        }]
      },
    };
    expect(() => validateDataBeforeIndexing(invalidUser))
      .toThrowError('Validation against schema failed on attribute [overrides]: mandatory field [entity_type] is not present');

    invalidUser = {
      ...user,
      user_confidence_level: {
        max_confidence: null, // mandatory field to null
        overrides: [{
          max_confidence: 77,
          entity_type: 'Report'
        }]
      },
    };
    expect(() => validateDataBeforeIndexing(invalidUser))
      .toThrowError('Validation against schema failed on attribute [max_confidence]: this mandatory field cannot be nil');

    const invalidThreatActorIndividual = {
      ...threatActorIndividual,
      height: [{
        // measure: 1.2192, // missing mandatory field in a multiple object
        date_seen: '2024-02-15T23:00:00.000Z'
      }],
    };
    expect(() => validateDataBeforeIndexing(invalidThreatActorIndividual))
      .toThrowError('Validation against schema failed on attribute [height]: mandatory field [measure] is not present');
  });
});

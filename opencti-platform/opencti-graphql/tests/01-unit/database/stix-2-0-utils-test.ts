import { describe, expect, it } from 'vitest';
import { buildStixId, convertTypeToStix2Type } from '../../../src/database/stix-2-0-converter';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../../../src/modules/case/feedback/feedback-types';

describe('convertTypeToStix2Type tests', () => {
  it('should return type', async () => {
    const types = [
      'Identity',
      'Location',
      'Threat-Actor',
      'StixFile',
      'Case-Incident',
      'Feedback',
      'Case-Rfi',
      'Case-Rft',
      'Task',
      'Data-Component',
      'Data-Source',
      'stix-sighting-relationship',
      'stix-core-relationship'
    ];
    const expectedTypes = [
      'identity',
      'location',
      'threat-actor',
      'file',
      'x-opencti-case-incident',
      'x-opencti-feedback',
      'x-opencti-case-rfi',
      'x-opencti-case-rft',
      'x-opencti-task',
      'x-mitre-data-component',
      'x-mitre-data-source',
      'sighting',
      'relationship'
    ];
    const result = types.map((type) => convertTypeToStix2Type(type));
    expect(result).toEqual(expectedTypes);
  });
});

describe('buildStixId tests', () => {
  it('should return id correctly formated', async () => {
    const customContainerId = buildStixId(ENTITY_TYPE_CONTAINER_FEEDBACK, 'feedback--ce07ddc6-2377-576b-ace5-a4de6996e789');
    expect(customContainerId).toEqual('x-opencti-feedback--ce07ddc6-2377-576b-ace5-a4de6996e789');

    const stixId = buildStixId(ENTITY_TYPE_CONTAINER_REPORT, 'report--87de3e34-b9a2-551d-a42f-d25a13d4ad0f');
    expect(stixId).toEqual('report--87de3e34-b9a2-551d-a42f-d25a13d4ad0f');
  });
});

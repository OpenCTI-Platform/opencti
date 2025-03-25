import { describe, expect, it } from 'vitest';
import { extractStixRepresentative } from '../../../src/database/stix-representative';
import type { StixObject } from '../../../src/types/stix-common';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_LOCATION_CITY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../src/schema/general';

describe('Stix representative tests', () => {
  it('Should return the representative of a stix object', async () => {
    const report = {
      name: 'My Report',
      extensions: {
        [STIX_EXT_OCTI]:
          {
            type: ENTITY_TYPE_CONTAINER_REPORT,
          },
      }
    } as unknown as StixObject;
    expect(extractStixRepresentative(report)).toEqual('My Report');
    const city = {
      name: 'My City',
      id: 'city--MyCity',
      extensions: {
        [STIX_EXT_OCTI]:
          {
            type: ENTITY_TYPE_LOCATION_CITY,
          },
      }
    } as unknown as StixObject;
    expect(extractStixRepresentative(city)).toEqual('My City');
    const externalReference = {
      name: 'My External Reference',
      source_name: 'source',
      external_id: '23',
      extensions: {
        [STIX_EXT_OCTI]:
          {
            type: ENTITY_TYPE_EXTERNAL_REFERENCE,
          },
      }
    } as unknown as StixObject;
    expect(extractStixRepresentative(externalReference)).toEqual('source (23)');
    const relationship = {
      name: 'My relationship',
      relationship_type: 'located-at',
      extensions: {
        [STIX_EXT_OCTI]:
          {
            type: ABSTRACT_STIX_CORE_RELATIONSHIP,
            source_value: 'T234',
            target_value: 'My City',
          },
      }
    } as unknown as StixObject;
    expect(extractStixRepresentative(relationship)).toEqual('T234 located-at My City');
  });
  it('Should return the representative of a stix relationship with restricted source/target', async () => {
    const relationship = {
      name: 'My relationship',
      relationship_type: 'located-at',
      extensions: {
        [STIX_EXT_OCTI]:
          {
            type: ABSTRACT_STIX_CORE_RELATIONSHIP,
            source_value: 'T234',
            target_value: 'My City',
          },
      }
    } as unknown as StixObject;
    expect(extractStixRepresentative(relationship, { fromRestricted: true, toRestricted: false })).toEqual('Restricted located-at My City');
    expect(extractStixRepresentative(relationship, { fromRestricted: false, toRestricted: true })).toEqual('T234 located-at Restricted');
    expect(extractStixRepresentative(relationship, { fromRestricted: true, toRestricted: true })).toEqual('Restricted located-at Restricted');
  });
  it('Should return the representative of a stix relationship with relationship arrow option', async () => {
    const relationship = {
      name: 'My relationship',
      relationship_type: 'located-at',
      extensions: {
        [STIX_EXT_OCTI]:
          {
            type: ABSTRACT_STIX_CORE_RELATIONSHIP,
            source_value: 'T234',
            target_value: 'My City',
          },
      }
    } as unknown as StixObject;
    expect(extractStixRepresentative(relationship, { fromRestricted: true, toRestricted: false }, true)).toEqual('Restricted ➡️ My City');
    expect(extractStixRepresentative(relationship, { fromRestricted: false, toRestricted: true }, true)).toEqual('T234 ➡️ Restricted');
    expect(extractStixRepresentative(relationship, { fromRestricted: true, toRestricted: true }, true)).toEqual('Restricted ➡️ Restricted');
  });
});

import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import type * as SDO from '../../../src/types/stix-2-1-sdo';
import { POSITION_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/locations/position';

describe('STIX 2.1 converter - location coordinates', () => {
  it('should keep a latitude and a longitude equal to 0', () => {
    const stix = convertStoreToStix_2_1({ ...POSITION_INSTANCE, latitude: 0, longitude: 0 } as any) as SDO.StixLocation;
    expect(stix.latitude).toEqual(0);
    expect(stix.longitude).toEqual(0);
  });
});
